from flask import Flask, render_template, request, send_file, make_response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import os
import pdfkit

app = Flask(__name__)
app.secret_key = 'secure_secret_key'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///marketing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login Manager Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# PDFKit Configuration
pdfkit_config = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')

# Campaign Model
class CampaignData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    channel = db.Column(db.String(50))
    spend = db.Column(db.Float)
    clicks = db.Column(db.Integer)
    impressions = db.Column(db.Integer)
    revenue = db.Column(db.Float)
    ctr = db.Column(db.Float)
    roi = db.Column(db.Float)
    filename = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    campaigns = db.relationship('CampaignData', backref='user', lazy=True)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Create DB tables
with app.app_context():
    db.create_all()

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            return "Username or email already exists.", 400

        hashed_pw = generate_password_hash(password)
        user = User(full_name=full_name, email=email, username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/')
        return "Invalid credentials", 401

    return render_template('login.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

# Home Page
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# Analyze CSV Route
@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    file = request.files.get('file')
    if not file or not file.filename.lower().endswith('.csv'):
        return "Please upload a valid .CSV file.", 400

    try:
        df = pd.read_csv(file)
        required_columns = {'Channel', 'Spend', 'Clicks', 'Impressions', 'Revenue'}
        if not required_columns.issubset(df.columns):
            return f"Missing columns: {', '.join(required_columns - set(df.columns))}", 400

        df = df[df['Impressions'] != 0]
        df['CTR'] = (df['Clicks'] / df['Impressions']).round(4)
        df = df[df['Spend'] != 0]
        df['ROI'] = (df['Revenue'] / df['Spend']).round(4)

        for _, row in df.iterrows():
            record = CampaignData(
                filename=file.filename,
                channel=row['Channel'],
                spend=row['Spend'],
                clicks=row['Clicks'],
                impressions=row['Impressions'],
                revenue=row['Revenue'],
                ctr=row['CTR'],
                roi=row['ROI'],
                user_id=current_user.id
            )
            db.session.add(record)
        db.session.commit()

        best_channel = df.loc[df['ROI'].idxmax(), 'Channel']
        best_roi = df['ROI'].max()
        avg_roi = round(df['ROI'].mean(), 4)
        top_ctr_channel = df.loc[df['CTR'].idxmax(), 'Channel']
        top_ctr_value = df['CTR'].max()

        return render_template('results.html',
                               table=df.to_html(classes='data', index=False),
                               best_channel=best_channel,
                               best_roi=best_roi,
                               avg_roi=avg_roi,
                               top_ctr_channel=top_ctr_channel,
                               top_ctr_value=top_ctr_value,
                               labels=df['Channel'].tolist(),
                               data=df['ROI'].tolist())
    except Exception as e:
        return f"Error: {e}", 500

# Records Page
@app.route('/records')
@login_required
def records():
    records = CampaignData.query.filter_by(user_id=current_user.id).all()
    return render_template('records.html', records=records)

# Download Excel
@app.route('/download_excel')
@login_required
def download_excel():
    records = CampaignData.query.filter_by(user_id=current_user.id).all()
    if not records:
        return "No records found.", 404

    df = pd.DataFrame([{
        'Filename': r.filename,
        'Channel': r.channel,
        'Spend': r.spend,
        'Clicks': r.clicks,
        'Impressions': r.impressions,
        'Revenue': r.revenue,
        'CTR': r.ctr,
        'ROI': r.roi
    } for r in records])

    filepath = 'marketing_report.xlsx'
    df.to_excel(filepath, index=False)
    return send_file(filepath, as_attachment=True)

# Download PDF
@app.route('/download_pdf')
@login_required
def download_pdf():
    records = CampaignData.query.filter_by(user_id=current_user.id).all()
    if not records:
        return "No records found.", 404

    try:
        rendered = render_template('pdf_template.html', records=records)
        pdf = pdfkit.from_string(rendered, False, configuration=pdfkit_config)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=marketing_report.pdf'
        return response
    except Exception as e:
        return f"PDF error: {e}", 500

# Run the App
if __name__ == '__main__':
    app.run(debug=True)
