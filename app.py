import os 
from flask import Flask, render_template, request, abort, send_file
from cmd import *
from flask.helpers import total_seconds


app =Flask(__name__)
app.config['UPLOAD_EXTENSIONS'] = ['.php']
app.config['TARGET_FILE'] = "target_file"
app.config['REPORT_FILE'] = 'report.pdf'

init("config.ini")

@app.route('/')
@app.route('/index.html')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    uploaded_file = request.files['target-file']
    classifier = request.form['classifier']
    vuln_type = request.form['vuln-type']

    save_target_file(uploaded_file)

    sqli_res = 0
    xss_res = 0
    if vuln_type == 'Both':
        sqli_res = cmd_predict_file(app.config['TARGET_FILE'], 'SQLi', classifier)[0]
        xss_res = cmd_predict_file(app.config['TARGET_FILE'], 'XSS', classifier)[0]
    elif vuln_type == 'SQLi':
        sqli_res = cmd_predict_file(app.config['TARGET_FILE'], 'SQLi', classifier)[0]
    elif vuln_type == 'XSS':
        xss_res = cmd_predict_file(app.config['TARGET_FILE'], 'XSS', classifier)[0]

    source_code = ''
    with open(app.config['TARGET_FILE']) as f:
        source_code = f.read()

    return render_template("index.html", source_code=source_code, classifier=classifier, vuln_type=vuln_type, sqli=sqli_res, xss=xss_res)


def save_target_file(uploaded_file):
    if uploaded_file.filename != '':
        file_ext = os.path.splitext(uploaded_file.filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            abort(400)
        uploaded_file.save(app.config['TARGET_FILE'])


@app.route('/report')
def download_report():
    # TODO
    # Call cmd_generate_report

    filepath = os.path.join(app.config['REPORT_FILE'])
    return send_file(filepath)

