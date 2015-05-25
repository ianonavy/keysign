import os
from flask import Flask, request, redirect, url_for, render_template, send_file
from subprocess import check_output
import zipfile
import shlex
import hashlib
from werkzeug import secure_filename


class Chdir:
    def __init__( self, newPath ):
        self.savedPath = os.getcwd()
        self.newPath = newPath

    def __enter__(self, *args, **kwargs):
        os.chdir(self.newPath)

    def __exit__( self, *args, **kwargs):
        os.chdir( self.savedPath )

def hashfile(filepath):
    sha1 = hashlib.sha1()
    f = open(filepath, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()


UPLOAD_FOLDER = 'uploads'
UPLOAD_KEYS_FOLDER = 'keys'
UPLOAD_ARCHIVE_FOLDER = 'signed_keys'
ALLOWED_EXTENSIONS = set(['asc'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ARCHIVE = os.path.join(app.config['UPLOAD_FOLDER'], 'csc_keys.zip')
ARCHIVE_ALL = os.path.join(app.config['UPLOAD_FOLDER'], 'csc_signed_keys.zip')


# make directories if they don't exist
for folder in (UPLOAD_KEYS_FOLDER, UPLOAD_ARCHIVE_FOLDER):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], folder)
    if not os.path.exists(full_path):
        os.makedirs(full_path)



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            full_path = os.path.join(app.config['UPLOAD_FOLDER'], UPLOAD_KEYS_FOLDER, filename)
            file.save(full_path)
            with zipfile.ZipFile(ARCHIVE, 'a') as archive:
                with Chdir(os.path.join(app.config['UPLOAD_FOLDER'])):
                    archive.write(os.path.join(UPLOAD_KEYS_FOLDER, filename))
            return redirect(url_for('upload_file'))
    archive_sum = hashfile(ARCHIVE) if os.path.exists(ARCHIVE) else ""
    signed_archive_sum = hashfile(ARCHIVE_ALL) if os.path.exists(ARCHIVE_ALL) else ""
    return render_template(
        'index.html',
        fingerprints=get_fingerprints(),
        ids=get_ids(),
        archive_sum=archive_sum,
        signed_archive_sum=signed_archive_sum)


@app.route('/signed_keys', methods=['GET', 'POST'])
def upload_signed_keys():
    if request.method == 'POST':
        file = request.files['file']
        sig = request.files['signature']
        if file and allowed_file(file.filename) and sig and allowed_file(sig.filename):
            filename = secure_filename(file.filename)
            sig_filename = secure_filename(sig.filename)
            full_path = os.path.join(app.config['UPLOAD_FOLDER'], UPLOAD_ARCHIVE_FOLDER, filename)
            file.save(full_path)
            full_path = os.path.join(app.config['UPLOAD_FOLDER'], UPLOAD_ARCHIVE_FOLDER, sig_filename)
            sig.save(full_path)
            with zipfile.ZipFile(ARCHIVE_ALL, 'a') as archive:
                with Chdir(os.path.join(app.config['UPLOAD_FOLDER'])):
                    archive.write(os.path.join(UPLOAD_ARCHIVE_FOLDER, filename))
                    archive.write(os.path.join(UPLOAD_ARCHIVE_FOLDER, sig_filename))
            return redirect(url_for('upload_file'))
    return redirect(url_for('upload_file'))


def get_fingerprints():
    html = '<table class="table">'
    html += '<tr><th>Filename</th><th>User ID</th><th>Key Fingerprint</th></tr>'
    with Chdir(app.config['UPLOAD_FOLDER']):
        for file_name in os.listdir(UPLOAD_KEYS_FOLDER):
            full_path = os.path.join(UPLOAD_KEYS_FOLDER, file_name)
            if '.gitignore' != file_name:
                fingerprint = check_output(shlex.split('/usr/bin/gpg --with-fingerprint ' + full_path)).decode('utf-8')
                id_ = fingerprint.split('\n')[0].split('/')[1][:8]
                fingerprint = fingerprint.split('\n')[1].split(' = ')[1]
                url = url_for('download_key', filename=file_name)
                file_name = "<a href='{}'>{}</a>".format(url, file_name)
                html += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(file_name, id_, fingerprint)
    html += '</table>'
    return html


def get_ids():
    ids = []
    with Chdir(app.config['UPLOAD_FOLDER']):
        for file_name in os.listdir(UPLOAD_KEYS_FOLDER):
            full_path = os.path.join(UPLOAD_KEYS_FOLDER, file_name)
            if '.gitignore' != file_name:
                fingerprint = check_output(shlex.split('/usr/bin/gpg --with-fingerprint ' + full_path)).decode('utf-8')
                id_ = fingerprint.split('\n')[0].split('/')[1][:8]
                ids.append(id_)
    return ids


@app.route('/download/<filename>')
def download_key(filename):
    return send_file(filename, as_attachment=True)


@app.route('/download')
def download_keys():
    return send_file(ARCHIVE, as_attachment=True)


@app.route('/download_signed')
def download_signed_keys():
    return send_file(ARCHIVE_ALL, as_attachment=True)


if __name__ == '__main__':
    app.run('0.0.0.0', debug=True)
