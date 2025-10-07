from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from extensions import db, login_manager
from flask import session
from flask import g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from functools import wraps
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # change this
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Password1672@localhost/rbac'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
login_manager.init_app(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # or use your provider
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'example@gmail.com'
app.config['MAIL_PASSWORD'] = 'paeljaj'  # Use app-specific password for Gmail
app.config['MAIL_DEFAULT_SENDER'] = 'example@gmail.com'


mail = Mail(app)



# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])




from models import User, Role, Device, DeviceData, DoctorPatient, HealthRemark, Prescription, NursePatient, Permission, RolePermission, Context, SQLAttackLog

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    roles = Role.query.filter(Role.name != 'Admin').all()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role_id = request.form['role']

        if is_sqli_attempt(username) or is_sqli_attempt(email) or is_sqli_attempt(password):
            log_sqli_attempt(f"Username: {username}, Email: {email}, Password: {password}")
            flash('Suspicious activity detected. Your request has been logged.')
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role_id=role_id,
            created_at=datetime.now()
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful. Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html', roles=roles)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if is_sqli_attempt(email) or is_sqli_attempt(password):
            log_sqli_attempt(f"Email: {email}, Password: {password}")
            flash('Suspicious activity detected. Your request has been logged.')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role.name

            # Redirect to role-based dashboard
            return redirect(url_for(f'dashboard_{user.role.name.lower()}'))
        else:
            flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/dashboard/user')
@login_required
def dashboard_user():
    if session['role'] != 'User':
        return redirect(url_for(f'dashboard_{session["role"].lower()}'))

    devices = Device.query.filter_by(user_id=session['user_id']).all()
    device_data = {}

    for device in devices:
        data = DeviceData.query.filter_by(device_id=device.id).all()
        device_data[device.id] = data
    return render_template('dashboard_user.html', devices=devices, device_data=device_data)


@app.route('/dashboard/doctor', methods=['GET', 'POST'])
@login_required
def dashboard_doctor():
    # Session check
    if 'username' not in session or session.get('role') != 'Doctor':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()

    context = Context.query.filter_by(user_id=user.id).first()
    if not context or (context.emergency_flag != 1 and not has_valid_context(user.id,request.remote_addr)):
        flash("Access denied: Invalid network or device score too low.", "danger")
        return redirect(url_for('login'))

    doctor_username = session['username']

    # Get assigned patients based on doctor’s username
    assignments = DoctorPatient.query.filter_by(doctor_username=doctor_username).all()
    patient_usernames = [a.patient_username for a in assignments]

    if not patient_usernames:
        flash('No patients assigned yet.', 'info')
        return render_template('dashboard_doctor.html', patient_data=[], patients=[], selected_patient=None)

    patients = User.query.filter(User.username.in_(patient_usernames)).all()

    # Select patient from dropdown (POST if selected)
    selected_patient_username = request.form.get('patient_username', type=str)
    if not selected_patient_username and patients:
        selected_patient_username = patients[0].username

    selected_patient = User.query.filter_by(username=selected_patient_username).first()
    context = Context.query.filter_by(user_id=selected_patient.id).first()

    # Get devices and health data for the selected patient
    device_data = []
    if selected_patient:
        devices = Device.query.filter_by(user_id=selected_patient.id).all()
        for device in devices:
            if context and context.emergency_flag == 1:
                data_entries = DeviceData.query.filter_by(device_id=device.id).all()
            else:
                data_entries = DeviceData.query.filter_by(device_id=device.id).order_by(DeviceData.recorded_at.desc()).limit(5).all()
            for entry in data_entries:
                prescription = Prescription.query.filter_by(
                    device_data_id=entry.id,
                    doctor_username=doctor_username,
                    patient_username=selected_patient.username
                ).first()
                nurse_remark = HealthRemark.query.filter_by(
                    device_data_id=entry.id,
                    patient_username=selected_patient.username).first()
                device_data.append({
                    'device': device,
                    'data': entry,
                    'prescription': prescription,
                    'remark': nurse_remark,
                    'id': entry.id
                })


    patient_data =  device_data if selected_patient else []

    return render_template(
        'dashboard_doctor.html',
        patient_data=patient_data,
        patients=patients,
        selected_patient=selected_patient
    )


@app.route('/dashboard/nurse', methods=['GET', 'POST'])
@login_required
def dashboard_trainer():
    if 'username' not in session or session.get('role') != 'Trainer':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()

    context = Context.query.filter_by(user_id=user.id).first()
    if not context or (context.emergency_flag != 1 and not has_valid_context(user.id,request.remote_addr)):
        flash("Access denied: Invalid network or device score too low.", "danger")
        return redirect(url_for('login'))

    nurse_username = session['username']

    # Get assigned patients from nurse_patient table
    assignments = NursePatient.query.filter_by(nurse_username=nurse_username).all()
    patient_usernames = [a.patient_username for a in assignments]

    if not patient_usernames:
        flash('No patients assigned yet.', 'info')
        return render_template('dashboard_trainer.html', patient_data=[], patients=[], selected_patient=None)

    patients = User.query.filter(User.username.in_(patient_usernames)).all()

    # Patient selection
    selected_patient_username = request.form.get('patient_username', type=str)
    if not selected_patient_username and patients:
        selected_patient_username = patients[0].username

    selected_patient = User.query.filter_by(username=selected_patient_username).first()
    context = Context.query.filter_by(user_id=selected_patient.id).first()

    # Fetch device data
    device_data = []
    if selected_patient:
        devices = Device.query.filter_by(user_id=selected_patient.id).all()
        for device in devices:
            if context and context.emergency_flag == 1:
                data_entries = DeviceData.query.filter_by(device_id=device.id).all()
            else:
                data_entries = DeviceData.query.filter_by(device_id=device.id).order_by(DeviceData.recorded_at.desc()).limit(5).all()
            for entry in data_entries:
                prescription = Prescription.query.filter_by(
                    device_data_id=entry.id,
                    patient_username=selected_patient.username
                ).first()
                remark = HealthRemark.query.filter_by(
                    device_data_id=entry.id,
                    nurse_username=nurse_username,
                    patient_username=selected_patient.username
                ).first()

                device_data.append({
                    'device': device,
                    'data': entry,
                    'prescription': prescription,
                    'remark': remark,
                    'id': entry.id
                })

    patient_data = device_data if selected_patient else []

    return render_template(
        'dashboard_trainer.html',
        patient_data=patient_data,
        patients=patients,
        selected_patient=selected_patient
    )


@app.route('/assign_nurse', methods=['POST'])
@login_required
def assign_nurse():
    if not has_permission(session.get('user_id'), 'assign_nurse'):
        flash('Access denied: You do not have permission to assign nurse .', 'danger')
        return redirect(url_for('dashboard_doctor'))
    if 'username' not in session or session.get('role') != 'Doctor':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    nurse_username = request.form.get('nurse_username')
    patient_username = request.form.get('patient_username')

    if not nurse_username or not patient_username:
        flash("Both nurse and patient usernames are required.", "danger")
        return redirect(url_for('dashboard_doctor'))

    # Check if nurse is already assigned
    existing_assignment = NursePatient.query.filter_by(
        nurse_username=nurse_username,
        patient_username=patient_username
    ).first()

    if existing_assignment:
        flash("This nurse is already assigned to the patient.", "info")
    else:
        new_assignment = NursePatient(
            nurse_username=nurse_username,
            patient_username=patient_username
        )
        db.session.add(new_assignment)
        db.session.commit()
        flash(f"Nurse {nurse_username} assigned to patient {patient_username}.", "success")

    return redirect(url_for('dashboard_doctor', patient_username=patient_username))



@app.route('/dashboard/admin', methods=['GET', 'POST'])
@login_required
def dashboard_admin():
    if session.get('role') != 'Admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    roles = Role.query.all()
    permissions = Permission.query.all()
    users = User.query.all()
    role_permissions = RolePermission.query.all()
    contexts = Context.query.all()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_role':
            if not has_permission(session.get('user_id'), 'manage_roles'):
                flash('Access denied: You do not have permission to add roles.', 'danger')
                return redirect(url_for('dashboard_admin'))
            role_name = request.form['role_name']
            if Role.query.filter_by(name=role_name).first():
                flash('Role already exists.', 'danger')
            else:
                new_role = Role(name=role_name)
                db.session.add(new_role)
                db.session.commit()
                flash('Role added successfully.', 'success')

        elif action == 'remove_role':
            if not has_permission(session.get('user_id'), 'manage_roles'):
                flash('Access denied: You do not have permission to add roles.', 'danger')
                return redirect(url_for('dashboard_admin'))
            role_id = request.form.get('role_id')
            # Query the database and remove the role
            role = Role.query.get(role_id)
            if role:
                db.session.delete(role)
                db.session.commit()
            flash('Role removed successfully', 'success')

        elif action == 'add_permission':
            if not has_permission(session.get('user_id'), 'manage_permissions'):
                flash('Access denied: You do not have permission to add permissions.', 'danger')
                return redirect(url_for('dashboard_admin'))
            permission_name = request.form['permission_name']
            permission_desc = request.form['permission_desc']
            if Permission.query.filter_by(name=permission_name).first():
                flash('Permission already exists.', 'danger')
            else:
                new_permission = Permission(name=permission_name, description=permission_desc)
                db.session.add(new_permission)
                db.session.commit()
                flash('Permission added successfully.', 'success')
        
        elif action == 'remove_permission':
            if not has_permission(session.get('user_id'), 'manage_permissions'):
                flash('Access denied: You do not have permission to add permissions.', 'danger')
                return redirect(url_for('dashboard_admin'))
            permission_id = request.form.get('permission_id')
            permission = Permission.query.get(permission_id)
            if permission:
                db.session.delete(permission)
                db.session.commit()
                flash(f'Permission "{permission.name}" removed successfully.', 'success')

        elif action == 'assign_permission':
            if not has_permission(session.get('user_id'), 'manage_roles_permissions'):
                flash('Access denied: You do not have permission to assign permissions to roles.', 'danger')
                return redirect(url_for('dashboard_admin'))
            role_id = request.form['role_id']
            permission_id = request.form['permission_id']
            if RolePermission.query.filter_by(role_id=role_id, permission_id=permission_id).first():
                flash('Permission already assigned to this role.', 'danger')
            else:
                role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
                db.session.add(role_permission)
                db.session.commit()
                flash('Permission assigned to role successfully.', 'success')

        elif action == 'assign_admin':
            if not has_permission(session.get('user_id'), 'manage_roles'):
                flash('Access denied: You do not have permission to grant admin access.', 'danger')
                return redirect(url_for('dashboard_admin'))
            user_id = request.form['user_id']
            user = User.query.get(user_id)
            if user:
                user.role_id = 4  # Assign 'Admin' role (assuming Admin has role_id = 1)
                db.session.commit()
                flash('User granted admin access successfully.', 'success')

        elif action == 'remove_role_permission':
            role_permission_id = request.form['role_permission_id']
            role_permission = RolePermission.query.get(role_permission_id)
            if role_permission:
                db.session.delete(role_permission)
                db.session.commit()
                flash('Role-Permission assignment removed successfully.', 'success')

        elif action == 'add_context':
            if not has_permission(session.get('user_id'), 'manage_device_context'):
                flash('Access denied: You do not have permission to update device context.', 'danger')
                return redirect(url_for('dashboard_admin'))
            user_id = request.form['user_id']
            network_type = request.form['network_type']
            emergency_flag = int(request.form['emergency_flag'])
            device_score = float(request.form['device_score'])

            existing = Context.query.filter_by(user_id=user_id).first()
            if existing:
                flash('Context for user already exists.', 'danger')
            else:
                new_context = Context(
                    user_id=user_id,
                    network_type=network_type,
                    emergency_flag=emergency_flag,
                    device_score=device_score
                )
                db.session.add(new_context)
                db.session.commit()
                flash('Context added successfully.', 'success')

        elif action == 'remove_context':
            if not has_permission(session.get('user_id'), 'manage_device_context'):
                flash('Access denied: You do not have permission to update device context.', 'danger')
                return redirect(url_for('dashboard_admin'))
            context_id = request.form['context_id']
            context_entry = Context.query.get(context_id)
            if context_entry:
                db.session.delete(context_entry)
                db.session.commit()
                flash('Context removed successfully.', 'success')

        db.session.commit()

    return render_template(
        'dashboard_admin.html',
        roles=roles,
        permissions=permissions,
        users=users,
        role_permissions=role_permissions,
        contexts=contexts
    )


@app.route('/remove_role_permission/<int:role_permission_id>', methods=['POST'])
@login_required
def remove_role_permission(role_permission_id):
    if not has_permission(session.get('user_id'), 'manage_roles_permissions'):
        flash('Access denied: You do not have permission to remove role-permission assignments.', 'danger')
        return redirect(url_for('dashboard_login'))
    if session.get('role') != 'Admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    role_permission = RolePermission.query.get_or_404(role_permission_id)
    
    if role_permission:
        db.session.delete(role_permission)
        db.session.commit()
        flash('Role-Permission assignment removed successfully.', 'success')
    else:
        flash('Role-Permission assignment not found.', 'danger')

    return redirect(url_for('dashboard_admin'))



# Remove role or permission
@app.route('/remove_role/<int:role_id>', methods=['GET'])
@login_required
def remove_role(role_id):
    if not has_permission(session.get('user_id'), 'manage_roles'):
        flash('Access denied: You do not have permission to remove roles.', 'danger')
        return redirect(url_for('dashboard_admin'))
    # Check if the logged-in user has an 'Admin' role using session
    if 'role' not in session or session['role'] != 'Admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    role = Role.query.get_or_404(role_id)

    # Ensure that the role being removed is not the 'Admin' role (to prevent accidental removal)
    if role.name == 'Admin':
        flash('You cannot remove the Admin role.', 'danger')
        return redirect(url_for('dashboard_admin'))

    db.session.delete(role)
    db.session.commit()
    flash('Role removed successfully.', 'success')
    return redirect(url_for('dashboard_admin'))

@app.route('/remove_permission/<int:permission_id>', methods=['GET'])
@login_required
def remove_permission(permission_id):
    # Check if the logged-in user has an 'Admin' role using 
    if not has_permission(session.get('user_id'), 'manage_permissions'):
        flash('Access denied: You do not have permission to remove permissions.', 'danger')
        return redirect(url_for('dashboard_admin'))
    if 'role' not in session or session['role'] != 'Admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    permission = Permission.query.get_or_404(permission_id)
    db.session.delete(permission)
    db.session.commit()
    flash('Permission removed successfully.', 'success')
    return redirect(url_for('dashboard_admin'))


@app.route('/register_device', methods=['GET', 'POST'])
@login_required
def register_device():
    user_role_id = session.get('user_id')  # Ensure this is set at login

    if not has_permission(user_role_id, 'write_device'):
        flash('Access denied: You do not have permission to register devices.', 'danger')
        return redirect(url_for('dashboard_user'))

    if request.method == 'POST':
        device_type = request.form['device_type']
        device_model = request.form['device_model']
        firmware_version = request.form['firmware_version']
        registered_on = datetime.now()

        new_device = Device(
            user_id=session['user_id'],
            device_type=device_type,
            device_model=device_model,
            firmware_version=firmware_version,
            registered_on=registered_on
        )
        db.session.add(new_device)
        db.session.commit()
        flash('Device registered successfully!')
        return redirect(url_for('dashboard_user'))

    return render_template('register_device.html')

from werkzeug.exceptions import BadRequest

@app.route('/upload_data/<device_id>', methods=['GET', 'POST'])
@login_required
def upload_data(device_id):
    if not has_permission(session.get('user_id'), 'write_data'):
        flash("Access denied: You do not have permission to upload health data.", 'danger')
        return redirect(url_for('dashboard_user'))
    device = Device.query.get_or_404(device_id)

    if device.user_id != session['user_id']:
        flash("You are not authorized to upload data for this device.")
        return redirect(url_for('dashboard_user'))

    if request.method == 'POST':
        try:
            heart_rate = int(request.form['heart_rate'])
            oxygen_level = float(request.form['oxygen_level'])
            steps = int(request.form['steps'])
            blood_pressure = request.form['blood_pressure']
            temperature = float(request.form['temperature'])

            # Validate blood pressure format (e.g., 120/80)
            if not re.match(r'^\d{1,3}/\d{1,3}$', blood_pressure):
                raise BadRequest("Invalid blood pressure format. Expected format: '120/80'.")

            recorded_at = datetime.now()

            # Create a new device data entry
            new_data = DeviceData(
                device_id=device.id,
                heart_rate=heart_rate,
                oxygen_level=oxygen_level,
                steps=steps,
                blood_pressure=blood_pressure,
                temperature=temperature,
                recorded_at=recorded_at
            )

            db.session.add(new_data)
            db.session.commit()
            user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            evaluate_emergency_for_user(session['user_id'],user_ip)
            flash('Health data uploaded successfully!')
            return redirect(url_for('dashboard_user'))
        
        except ValueError:
            flash("Please enter valid numbers for health metrics.")
        except BadRequest as e:
            flash(str(e))

    return render_template('upload_data.html', device=device)


@app.route('/add_prescription/<int:data_id>', methods=['POST'])
@login_required
def add_prescription(data_id):
    user_role_id = session.get('user_id')  # Ensure role_id is set in session at login

    if not has_permission(user_role_id, 'write_prescription'):
        flash('Access denied: Missing permission to write prescription.', 'danger')
        return redirect(url_for('dashboard_doctor'))

    prescription_text = request.form['prescription']
    patient_username = request.form.get('patient_username')
    if not patient_username:
        flash('Patient not specified.', 'danger')
        return redirect(url_for('dashboard_doctor'))

    # Check for existing prescription
    existing_prescription = Prescription.query.filter_by(
        doctor_username=session['username'],
        patient_username=patient_username,
        device_data_id=data_id
    ).first()

    if existing_prescription:
        existing_prescription.prescription = prescription_text
        flash('Prescription updated.', 'info')
    else:
        new_prescription = Prescription(
            doctor_username=session['username'],
            patient_username=patient_username,
            device_data_id=data_id,
            prescription=prescription_text
        )
        db.session.add(new_prescription)
        flash('Prescription added.', 'success')

    db.session.commit()

    # Redirect back to the same patient
    return redirect(url_for('dashboard_doctor', patient_username=patient_username))

@app.route('/add_remark/<int:data_id>', methods=['POST'])
@login_required
def add_remark(data_id):
    user_role_id = session.get('user_id')  # Make sure role_id is stored in session during login
    if not has_permission(user_role_id, 'write_remark'):
        flash('Access denied: Missing permission to write remark.', 'danger')
        return redirect(url_for('dashboard_trainer'))

    remark_text = request.form['remark']
    patient_username = request.form.get('patient_username')

    if not patient_username:
        flash('Patient not specified.', 'danger')
        return redirect(url_for('dashboard_trainer'))

    # Check for existing remark
    existing_remark = HealthRemark.query.filter_by(
        nurse_username=session['username'],
        patient_username=patient_username,
        device_data_id=data_id
    ).first()

    if existing_remark:
        existing_remark.remark = remark_text
        flash('Remark updated.', 'info')
    else:
        new_remark = HealthRemark(
            nurse_username=session['username'],
            patient_username=patient_username,
            device_data_id=data_id,
            remark=remark_text
        )
        db.session.add(new_remark)
        flash('Remark added.', 'success')

    db.session.commit()

    # Redirect back to the same patient
    return redirect(url_for('dashboard_trainer', selected_patient_username = patient_username))




@app.route('/dashboard/doctor/assign_patient', methods=['POST'])
@login_required
def assign_patient():
    if not has_permission(session.get('user_id'), 'add_patients'):
        flash('Access denied: You do not have permission to assign patients.', 'danger')
        return redirect(url_for('dashboard_doctor'))
    if session['role'] != 'Doctor':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    new_patient_username = request.form.get('new_patient_username')

    # Ensure the user exists
    patient = User.query.filter_by(username=new_patient_username).first()
    if patient:
        doctor_assignment = DoctorPatient(
            doctor_username=session['username'],
            patient_username=new_patient_username
        )
        db.session.add(doctor_assignment)
        db.session.commit()
        flash(f'Patient {new_patient_username} assigned successfully!', 'success')
    else:
        flash(f'Patient {new_patient_username} does not exist.', 'danger')

    return redirect(url_for('dashboard_doctor'))  # Redirect back to the doctor dashboard



@app.route('/update_device_context', methods=['POST'])
@login_required
def update_device_context():
    if not has_permission(session.get('user_id'), 'manage_device_context'):
        flash('Access denied: You do not have permission to update device context.', 'danger')
        return redirect(url_for('dashboard_admin'))
    network_type = request.form['network_type']
    device_score = float(request.form['device_score'])
    emergency_flag = int(request.form['emergency_flag'])

    # Update or insert context data
    context = Context(user_id=current_user.id, network_type=network_type, device_score=device_score, emergency_flag=emergency_flag)
    db.session.add(context)
    db.session.commit()

    flash('Device context updated successfully.', 'success')
    return redirect(url_for('dashboard'))





import re
from datetime import datetime

# Define a function to check for SQL Injection patterns
def is_sqli_attempt(user_input):
    # Patterns of common SQL Injection attacks
    sqli_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|REPAIR|SHOW|DESCRIBE|EXPLAIN)\b)",
        r"(--|#|\*/|\*\/|\bOR\b|\bAND\b)",  # Comments or logical operators
        r"('[^']*')",  # Strings enclosed in single quotes
        r"(=|;|')",  # Common SQL delimiters
        r"\b(UNION|NULL|IS|DATABASE|LIKE)\b"  # UNION-based attacks and common SQL keywords
    ]
    
    for pattern in sqli_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False


def log_sqli_attempt(user_input):
    ip_address = request.remote_addr  # Get the IP address of the user making the request
    timestamp = datetime.now()  # Current timestamp
    
    # Create a new log entry
    log_entry = SQLAttackLog(
        ip_address=ip_address,
        input_text=user_input,
        timestamp=timestamp
    )
    
    # Add the log entry to the session and commit to the database
    db.session.add(log_entry)
    db.session.commit()
    suspicious_logs_count = SQLAttackLog.query.filter_by(ip_address=ip_address).count()

    if suspicious_logs_count > 10:
        # Send an email to admin if more than 10 suspicious entries are found
        send_admin_notification(ip_address)

def send_admin_notification(ip_address):
    # Email configuration
    admin_email = "admin@eg.com"  # Replace with the actual admin email
    subject = "Suspicious Network Detected"
    body = f"Alert: The network with IP address {ip_address} has triggered more than 10 suspicious SQLi attempts. It is recommended to review and remove this network from the context."

    # Create the message
    msg = Message(subject=subject, recipients=[admin_email])
    msg.body = body

    # Send email
    try:
        mail.send(msg)
        print(f"Admin notification sent for suspicious network: {ip_address}")
    except Exception as e:
        print(f"Error sending email: {e}")


def has_valid_context(user_id, required_network, min_score=90.0):
    context = Context.query.filter_by(user_id=user_id).first()
    if not context:
        return False

    return context.network_type == required_network and context.device_score >= min_score

def has_permission(user_id, permission_name):
    user = User.query.get(user_id)
    permission = Permission.query.filter_by(name=permission_name).first()
    if not permission:
        return False
    return RolePermission.query.filter_by(role_id=user.role_id, permission_id=permission.id).first() is not None

import requests

def get_location_from_ip(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        data = response.json()
        if data['status'] == 'success':
            city = data.get('city', '')
            region = data.get('regionName', '')
            country = data.get('country', '')
            return f"{city}, {region}, {country}"
        else:
            return "Location unavailable"
    except Exception:
        return "Error getting location"

def evaluate_emergency_for_user(user_id,ip=None):
    # Get last 5 records for all devices of the user
    data_points = DeviceData.query.join(Device).filter(Device.user_id == user_id)\
        .order_by(DeviceData.recorded_at.desc()).limit(5).all()

    if len(data_points) < 5:
        return  # Not enough data to make a decision

    avg_hr = sum(d.heart_rate for d in data_points) / 5
    avg_o2 = sum(d.oxygen_level for d in data_points) / 5
    avg_temp = sum(d.temperature for d in data_points) / 5

    emergency = (
        avg_hr < 50 or avg_hr > 150 or
        avg_o2 < 90 or
        avg_temp > 39 or avg_temp < 36
    )


    context = Context.query.filter_by(user_id=user_id).first()
    if context:
        context.emergency_flag = 1 if emergency else 0
    else:
        context = Context(
            user_id=user_id,
            network_type="unknown",
            device_score=0.0,
            emergency_flag=1 if emergency else 0
        )
        db.session.add(context)
    if emergency:
        patient = User.query.get(user_id)
        message = f"Emergency alert for patient '{patient.username}' based on latest health data."
        location = get_location_from_ip(ip) if ip else "Location not available"
        # Notify assigned doctors
        assigned_doctors = DoctorPatient.query.filter_by(patient_username=patient.username).all()
        for assignment in assigned_doctors:
            doctor = User.query.filter_by(username=assignment.doctor_username).first()
            if doctor:
                send_emergency_email(doctor.email, patient.username, location)

        # Notify assigned nurses
        assigned_nurses = NursePatient.query.filter_by(patient_username=patient.username).all()
        for assignment in assigned_nurses:
            nurse = User.query.filter_by(username=assignment.nurse_username).first()
            if nurse:
                send_emergency_email(nurse.email, patient.username, location)

    db.session.commit()

def send_emergency_email(to_email, patient_name, location=None):
    subject = "🚨 Emergency Alert: Patient Critical"
    
    location_text = f"Location: {location}\n\n" if location else ""

    body = f"""
    Attention,

    The health data of patient '{patient_name}' has triggered an emergency alert.
    {location_text}
    Please review their data immediately.

    - Health Monitoring System
    """

    msg = Message(subject, recipients=[to_email], body=body)
    mail.send(msg)




if __name__ == '__main__':
    app.run(debug=True)

