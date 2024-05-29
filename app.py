import os
from flask import Flask, request, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename
import olefile
from pdfid import pdfid
from pdfid.pdfid import PDFiD
import zipfile

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'supersecretkey'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_ole(file_path):
    try:
        ole = olefile.OleFileIO(file_path)
        if ole.exists('macros'):
            return True, "Macros found"
        if ole.exists('word/vbaProject.bin'):
            return True, "VBA project found"
    except Exception as e:
        return False, f"Error reading OLE file: {e}"
    return False, "No malicious indicators found"

def check_pdf(file_path):
    try:
        pdf = PDFiD(file_path)
        for keyword in pdf.keywords:
            if keyword.count > 0:
                return True, f"Suspicious keyword found: {keyword.name}"
    except Exception as e:
        return False, f"Error reading PDF file: {e}"
    return False, "No malicious indicators found"

def check_zip(file_path):
    try:
        with zipfile.ZipFile(file_path, 'r') as archive:
            for name in archive.namelist():
                if name.endswith('.bin') or name.endswith('.vbaProject'):
                    return True, f"Suspicious file found inside archive: {name}"
    except Exception as e:
        return False, f"Error reading ZIP file: {e}"
    return False, "No malicious indicators found"

def check_jar(file_path):
    try:
        with zipfile.ZipFile(file_path, 'r') as jarfile:
            for name in jarfile.namelist():
                if name.endswith('.class'):
                    return True, f"Suspicious class file found inside JAR: {name}"
    except Exception as e:
        return False, f"Error reading JAR file: {e}"
    return False, "No malicious indicators found in JAR file"

def analyze_file(file_path):
    file_type = os.path.splitext(file_path)[1].lower()
    if file_type == '.pdf':
        is_malicious, reason = check_pdf(file_path)
    elif file_type in ['.docx', '.pptx', '.xlsx']:
        is_malicious, reason = check_zip(file_path)
    elif file_type in ['.doc', '.xls', '.ppt']:
        is_malicious, reason = check_ole(file_path)
    elif file_type == '.jar':
        is_malicious, reason = check_jar(file_path)
    else:
        is_malicious, reason = False, "Unsupported file type"
    return is_malicious, reason

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            is_malicious, reason = analyze_file(filepath)
            return render_template('result.html', filename=filename, is_malicious=is_malicious, reason=reason)
    return render_template('upload.html')

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
