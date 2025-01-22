from flask import Flask, request, jsonify
import jwt
import datetime
import mysql.connector
import bcrypt
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Para permitir peticiones desde el frontend

SECRET_KEY = 'mi_clave_secreta'


# Configuración de la conexión a la base de datos MySQL
def get_db_connection():
    connection = mysql.connector.connect(
        host='localhost',
        user='root',  # Cambia por tu usuario de MySQL
        password='',  # Cambia por tu contraseña de MySQL
        database='autenticacion'  # Nombre de tu base de datos
    )
    return connection


# Función para hashear contraseñas
def hash_password(password):
    """Genera un hash de la contraseña utilizando bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


# Función para verificar la contraseña
def check_password(stored_password, password):
    """Verifica si la contraseña almacenada coincide con la ingresada"""
    return bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8'))

# Verificar si el rol del usuario es 'ADMIN'
def check_admin_role(decoded_token):
    if decoded_token.get('role') != 'ADMIN':
        return False
    return True


@app.route('/admin/data', methods=['GET'])
def admin_data():
    """Ruta protegida que solo puede ser accedida por administradores"""
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token es requerido'}), 403

    try:
        # Decodificamos el token
        data = jwt.decode(token.split()[1], SECRET_KEY, algorithms=["HS256"])

        # Verificamos si el usuario es admin
        if not check_admin_role(data):
            return jsonify({'message': 'Acceso denegado. Solo administradores pueden acceder.'}), 403

        return jsonify({'message': 'Datos de administración.'})

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token inválido'}), 403


@app.route('/register', methods=['POST'])
def register():
    """Registrar un nuevo usuario con contraseña hasheada"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'USER')

    # Hashear la contraseña
    hashed_password = hash_password(password)

    # Conectar a la base de datos y guardar el nuevo usuario
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO usuarios (username, password, email, role, enabled) VALUES (%s, %s, %s, %s, %s)",
        (username, hashed_password, email, role, True)  # Por defecto, enabled es True
    )
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'message': 'Usuario registrado exitosamente'}), 201


@app.route('/login', methods=['POST'])
def login():
    """Iniciar sesión y devolver un JWT si las credenciales son correctas"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Conectar a la base de datos y obtener el usuario
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE username = %s AND enabled = TRUE", (username,))
    user = cursor.fetchone()

    if user and check_password(user['password'], password):  # Verificamos la contraseña hasheada
        token = jwt.encode(
            {'username': username, 'role': user['role'],
             'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            SECRET_KEY, algorithm="HS256")
        cursor.close()
        conn.close()
        return jsonify({'token': token})

    cursor.close()
    conn.close()
    return jsonify({'message': 'Usuario o contraseña incorrectos'}), 401


@app.route('/protected', methods=['GET'])
def protected():
    """Endpoint protegido por JWT"""
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token es requerido'}), 403

    try:
        data = jwt.decode(token.split()[1], SECRET_KEY, algorithms=["HS256"])
        return jsonify({'message': f'Bienvenido {data["username"]}'})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token inválido'}), 403


if __name__ == '__main__':
    app.run(debug=True)
