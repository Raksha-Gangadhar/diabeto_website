from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps  # Add this import for the admin_required decorator
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///diabetes_app.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # New field for admin status
    # Relationship to test results
    test_results = db.relationship('TestResult', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

class TestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    gender = db.Column(db.String(10), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    glucose = db.Column(db.Float, nullable=False)
    bmi = db.Column(db.Float, nullable=False)
    sys_bp = db.Column(db.Float, nullable=False)
    dia_bp = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)  # Numerical score for the chart
    
    def __repr__(self):
        return f'<TestResult {self.id} for User {self.user_id}>'

# Admin-required decorator - use this to protect admin routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Home page route (index)
@app.route("/")
def index():
    return render_template("index.html")

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("profile"))
        else:
            return render_template("login.html", error="Invalid credentials. Try again.")
    return render_template("login.html")

# Signup route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template("signup.html", error="Email already registered. Please use a different email.")
        
        # Check if passwords match
        if password != confirm_password:
            return render_template("signup.html", error="Passwords do not match. Please try again.")
            
        # Create new user
        password_hash = generate_password_hash(password)
        new_user = User(name=name, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("signup.html")

# Profile route (after login)
@app.route("/profile")
@login_required
def profile():
    # Get the user's test history
    test_history = TestResult.query.filter_by(user_id=current_user.id).order_by(TestResult.date.desc()).limit(5).all()
    
    # Format the data for the chart
    chart_dates = []
    chart_scores = []
    chart_colors = []
    
    # Prepare data for template
    history_data = []
    
    for test in test_history:
        # Format date for chart
        chart_dates.append(test.date.strftime('%b %d'))
        chart_scores.append(test.risk_score)
        
        # Set color based on risk level
        if test.risk_level == "Low Risk":
            chart_colors.append('#22c55e')  # Green
        elif test.risk_level == "At Risk":
            chart_colors.append('#f59e0b')  # Orange/Yellow
        else:
            chart_colors.append('#ef4444')  # Red
        
        # Format data for history list
        history_data.append({
            'id': test.id,
            'date': test.date.strftime('%b %d, %Y'),
            'risk_level': test.risk_level,
            'risk_class': 'risk-low' if test.risk_level == "Low Risk" else 
                           'risk-medium' if test.risk_level == "At Risk" else 'risk-high'
        })
    
    # Reverse lists for the chart (oldest to newest)
    chart_dates.reverse()
    chart_scores.reverse()
    chart_colors.reverse()
    
    # Create user context
    user = {
        'id': current_user.id,
        'name': current_user.name,
        'email': current_user.email
    }
    
    return render_template(
        "profile.html", 
        user=user, 
        test_history=history_data,
        chart_dates=chart_dates,
        chart_scores=chart_scores,
        chart_colors=chart_colors,
        has_tests=len(history_data) > 0
    )

# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Form route (to assess diabetes risk)
@app.route("/form", methods=["GET", "POST"])
@login_required
def form():
    if request.method == "POST":
        # Extract form data
        gender = request.form["gender"]
        age = int(request.form["age"])
        glucose = float(request.form["glucose"])
        bmi = float(request.form["bmi"])
        sys_bp = float(request.form["sys_bp"])
        dia_bp = float(request.form["dia_bp"])

        # Calculate the risk score (for the chart)
        # This is a simple calculation - you might want to use a more sophisticated algorithm
        risk_score = 0
        
        # Add to risk score based on age
        if age > 60:
            risk_score += 1.5
        elif age > 45:
            risk_score += 1.0
        else:
            risk_score += 0.5
            
        # Add to risk score based on gender (slightly higher for males)
        if gender == "male":
            risk_score += 0.5
        else:
            risk_score += 0.3
            
        # Add to risk score based on glucose
        if glucose > 180:
            risk_score += 3.0
        elif glucose > 140:
            risk_score += 2.0
        else:
            risk_score += 0.8
            
        # Add to risk score based on BMI
        if bmi > 30:
            risk_score += 2.0
        elif bmi > 25:
            risk_score += 1.5
        else:
            risk_score += 0.5
            
        # Add to risk score based on systolic blood pressure
        if sys_bp > 140:
            risk_score += 1.5
        elif sys_bp > 130:
            risk_score += 1.0
        else:
            risk_score += 0.5
            
        # Add to risk score based on diastolic blood pressure
        if dia_bp > 90:
            risk_score += 1.5
        elif dia_bp > 85:
            risk_score += 1.0
        else:
            risk_score += 0.5
        
        # Determine risk level based on the highest risk factor
        if glucose > 180 or bmi > 30 or sys_bp > 140 or dia_bp > 90:
            risk_level = "High Risk"
        elif glucose > 140 or bmi > 25 or sys_bp > 130 or dia_bp > 85:
            risk_level = "At Risk"
        else:
            risk_level = "Low Risk"
        
        # Save test result to database
        new_test = TestResult(
            user_id=current_user.id,
            gender=gender,
            age=age,
            glucose=glucose,
            bmi=bmi,
            sys_bp=sys_bp,
            dia_bp=dia_bp,
            risk_level=risk_level,
            risk_score=risk_score
        )
        db.session.add(new_test)
        db.session.commit()
        
        # Redirect to the result page with the risk level
        return redirect(url_for("result", risk_level=risk_level))

    return render_template("form.html")

# Result page route (after form submission)
@app.route("/result")
@login_required
def result():
    risk_level = request.args.get("risk_level", default="Low Risk", type=str)
    return render_template("result.html", risk_level=risk_level)

# Test details route
@app.route("/test_details/<int:test_id>")
@login_required
def test_details(test_id):
    # Get the test with the specified ID, ensure it belongs to the current user
    test = TestResult.query.filter_by(id=test_id, user_id=current_user.id).first_or_404()
    
    # Format the test data for display
    test_data = {
        'id': test.id,
        'date': test.date.strftime('%B %d, %Y'),
        'gender': test.gender.capitalize(),
        'age': test.age,
        'glucose': test.glucose,
        'bmi': test.bmi,
        'systolic_bp': test.sys_bp,
        'diastolic_bp': test.dia_bp,
        'risk_level': test.risk_level,
        'risk_score': test.risk_score
    }
    
    return render_template("test_details.html", test=test_data)

# Delete test route
@app.route("/delete_test/<int:test_id>", methods=["POST"])
@login_required
def delete_test(test_id):
    # Get the test with the specified ID, ensure it belongs to the current user
    test = TestResult.query.filter_by(id=test_id, user_id=current_user.id).first_or_404()
    
    # Delete the test
    db.session.delete(test)
    db.session.commit()
    
    # Return to profile page
    return redirect(url_for('profile'))

# Diet Plan page route
@app.route("/diet_plan")
@login_required
def diet_plan():
    risk_level = request.args.get('risk_level', default="Low Risk", type=str)
    return render_template("diet_plan.html", risk_level=risk_level)

# Admin routes
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    # Get counts for the dashboard
    user_count = User.query.count()
    test_count = TestResult.query.count()
    high_risk_count = TestResult.query.filter_by(risk_level="High Risk").count()
    
    return render_template(
        "admin/dashboard.html", 
        user_count=user_count,
        test_count=test_count,
        high_risk_count=high_risk_count
    )

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template("admin/users.html", users=users)

@app.route("/admin/tests")
@login_required
@admin_required
def admin_tests():
    tests = TestResult.query.order_by(TestResult.date.desc()).all()
    
    # Format the data for template
    tests_data = []
    for test in tests:
        user = User.query.get(test.user_id)
        tests_data.append({
            'id': test.id,
            'user_id': test.user_id,
            'user_name': user.name if user else "Unknown",
            'user_email': user.email if user else "Unknown",
            'date': test.date.strftime('%b %d, %Y'),
            'risk_level': test.risk_level,
            'risk_class': 'risk-low' if test.risk_level == "Low Risk" else 
                          'risk-medium' if test.risk_level == "At Risk" else 'risk-high'
        })
    
    return render_template("admin/tests.html", tests=tests_data)

@app.route("/admin/user/<int:user_id>")
@login_required
@admin_required
def admin_user_details(user_id):
    user = User.query.get_or_404(user_id)
    tests = TestResult.query.filter_by(user_id=user_id).order_by(TestResult.date.desc()).all()
    
    # Format the data for template
    tests_data = []
    for test in tests:
        tests_data.append({
            'id': test.id,
            'date': test.date.strftime('%b %d, %Y'),
            'risk_level': test.risk_level,
            'risk_class': 'risk-low' if test.risk_level == "Low Risk" else 
                          'risk-medium' if test.risk_level == "At Risk" else 'risk-high'
        })
    
    return render_template("admin/user_details.html", user=user, tests=tests_data)

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Don't allow admin to delete themselves
    if user.id == current_user.id:
        flash("You cannot delete your own admin account.")
        return redirect(url_for('admin_users'))
    
    # Delete all test results associated with the user
    TestResult.query.filter_by(user_id=user_id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User {user.email} and all associated data have been deleted.")
    return redirect(url_for('admin_users'))

@app.route("/admin/test/<int:test_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_test(test_id):
    test = TestResult.query.get_or_404(test_id)
    user_id = test.user_id
    
    # Delete the test
    db.session.delete(test)
    db.session.commit()
    
    flash(f"Test ID {test_id} has been deleted.")
    # Return to tests page
    return redirect(url_for('admin_tests'))

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def admin_make_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    
    flash(f"User {user.email} has been granted admin privileges.")
    return redirect(url_for('admin_users'))

@app.route("/admin/remove_admin/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def admin_remove_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    # Don't allow admin to remove their own admin status
    if user.id == current_user.id:
        flash("You cannot remove your own admin privileges.")
        return redirect(url_for('admin_users'))
    
    user.is_admin = False
    db.session.commit()
    
    flash(f"Admin privileges removed from user {user.email}.")
    return redirect(url_for('admin_users'))

# Function to create the first admin user
def create_admin(email, password, name="Admin"):
    # Check if admin exists
    admin = User.query.filter_by(email=email).first()
    if admin:
        # If user exists but is not admin, make them admin
        if not admin.is_admin:
            admin.is_admin = True
            db.session.commit()
        return admin
    
    # Create new admin user
    password_hash = generate_password_hash(password)
    new_admin = User(name=name, email=email, password_hash=password_hash, is_admin=True)
    db.session.add(new_admin)
    db.session.commit()
    return new_admin

# Load user from user ID (for Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Creates the database tables if they don't exist
        
        # Check if is_admin column exists already
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        columns = [column['name'] for column in inspector.get_columns('user')]
        
        # If is_admin column doesn't exist, add it
        if 'is_admin' not in columns:
            try:
                from sqlalchemy import text
                db.session.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT FALSE"))
                db.session.commit()
                print("Added is_admin column to user table")
            except Exception as e:
                db.session.rollback()
                print(f"Error adding is_admin column: {e}")
        
        # Try to create admin user
        try:
            admin_email = "admin@example.com"  # Change this to your email if needed
            create_admin(email=admin_email, password="adminpassword123", name="Admin User")
            print(f"Admin user {admin_email} created or updated")
        except Exception as e:
            print(f"Error creating admin: {e}")
            
    app.run(debug=True)