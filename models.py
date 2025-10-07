from extensions import db
from flask_login import UserMixin
from datetime import datetime


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    role = db.relationship('Role', backref=db.backref('users', lazy=True))
    def __repr__(self):
        return f'<User {self.username}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    device_model = db.Column(db.String(100), nullable=False)
    firmware_version = db.Column(db.String(50))
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('devices', lazy=True))

class DeviceData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    heart_rate = db.Column(db.Integer)
    oxygen_level = db.Column(db.Float)
    steps = db.Column(db.Integer)
    blood_pressure = db.Column(db.String(20))
    temperature = db.Column(db.Float)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)

    device = db.relationship('Device', backref=db.backref('data_entries', lazy=True))

class DoctorPatient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_username = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)
    patient_username = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)

    doctor = db.relationship('User', foreign_keys=[doctor_username], backref=db.backref('assigned_patients', lazy=True))
    patient = db.relationship('User', foreign_keys=[patient_username])


class HealthRemark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nurse_username = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)
    patient_username = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)
    device_data_id = db.Column(db.Integer, db.ForeignKey('device_data.id'), nullable=False)
    remark = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    nurse = db.relationship('User', foreign_keys=[nurse_username], backref=db.backref('remarks_given', lazy=True))
    patient = db.relationship('User', foreign_keys=[patient_username], backref=db.backref('remarks_received', lazy=True))
    device_data = db.relationship('DeviceData', backref=db.backref('nurse_remarks', lazy=True))


class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_username = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)
    patient_username = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)
    device_data_id = db.Column(db.Integer, db.ForeignKey('device_data.id'), nullable=False)
    prescription = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    doctor = db.relationship('User', foreign_keys=[doctor_username], backref=db.backref('prescriptions_given', lazy=True))
    patient = db.relationship('User', foreign_keys=[patient_username], backref=db.backref('prescriptions_received', lazy=True))
    device_data = db.relationship('DeviceData', backref=db.backref('prescriptions', lazy=True))

class NursePatient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nurse_username = db.Column(db.String(100), nullable=False)
    patient_username = db.Column(db.String(100), nullable=False)



class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)

    def __repr__(self):
        return f'<Permission {self.name}>'

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f'<Role {self.name}>'

class RolePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'), nullable=False)

    role = db.relationship('Role', backref=db.backref('permissions', lazy=True))
    permission = db.relationship('Permission', backref=db.backref('roles', lazy=True))

class Context(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    network_type = db.Column(db.String(50))
    emergency_flag = db.Column(db.Boolean, default=False)  # Emergency flag (0 or 1)
    device_score = db.Column(db.Float)

    user = db.relationship('User', backref='context', lazy=True)

class SQLAttackLog(db.Model):
    __tablename__ = 'sql_attack_log'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(50), nullable=False)
    input_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    
    def __repr__(self):
        return f"<SQLAttackLog {self.id}>"    