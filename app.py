from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "clave_secreta"
# Lista temporal para guardar las entregas pendientes de validar
solicitudes_pendientes = []
# --- CONEXIÓN BASE DE DATOS ---
def get_db_connection():
    conn = sqlite3.connect("revive.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # --- Tabla Usuarios ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            points INTEGER DEFAULT 0
        )
    """)
    
    # --- Tabla Productos ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            points_cost INTEGER NOT NULL,
            image TEXT,
            stock INTEGER DEFAULT 100,
            active INTEGER DEFAULT 1
        )
    """)
    
    # --- Tabla Canjes ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS redemptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            points_spent INTEGER NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pendiente',
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    """)

    # --- Tabla Materiales ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            points_per_kg INTEGER NOT NULL,
            requirements TEXT
        )
    """)

    # ✅ NUEVO: Agregar columna requirements si no existe (Manejo de errores)
    try:
        conn.execute('ALTER TABLE materials ADD COLUMN requirements TEXT DEFAULT "Limpio y seco"')
    except:
        # Si ya existe la columna, no hace nada
        pass

    # --- Tabla Historial de Ventas (Entregas) ---
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            material_name TEXT,
            weight REAL,
            points_earned INTEGER,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # --- Tabla Admins ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    
    # --- Datos Demo: Productos ---
    existing = conn.execute('SELECT COUNT(*) FROM products').fetchone()[0]
    if existing == 0:
        products = [
            ('Kit Ecológico', 150, 'imagen de reciclaje2.jpeg', 50),
            ('Libreta Reciclada', 80, 'imagen de reciclaje3.jpeg', 100),
            ('Bolsa Reutilizable', 50, 'imagen de reciclaje4.jpeg', 200)
        ]
        conn.executemany(
            'INSERT INTO products (name, points_cost, image, stock) VALUES (?, ?, ?, ?)',
            products
        )

    # --- Datos Demo: Admin ---
    admin_count = conn.execute('SELECT COUNT(*) FROM admins').fetchone()[0]
    if admin_count == 0:
        default_user = 'admin'
        password_hash = generate_password_hash('admin123')
        conn.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)', (default_user, password_hash))
        print("Usuario admin creado: admin / admin123")
        
    conn.commit()
    conn.close()
# --- DECORADOR PARA PROTEGER RUTAS ADMIN ---
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Acceso denegado. Inicia sesión como administrador.', 'error')
            return redirect(url_for('admin_login'))
        return func(*args, **kwargs)
    return wrapper

# --- RUTAS PÚBLICAS Y LOGIN ---

@app.route('/')
def index():
    return redirect(url_for('login'))
# --- RUTA PARA QUE EL USUARIO ENVÍE MATERIAL ---
@app.route('/enviar_material', methods=['POST'])
def enviar_material():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    material = request.form.get('material')
    cantidad = request.form.get('cantidad')
    puntos_estimados = int(cantidad) * 10 

    # Agregamos a la lista de pendientes (NO sumamos puntos todavía)
    nueva_solicitud = {
        "id": len(solicitudes_pendientes) + 1,
        "user_id": session['user_id'],
        "username": session.get('username', 'Usuario'),
        "material": material,
        "puntos": puntos_estimados
    }
    solicitudes_pendientes.append(nueva_solicitud)
    
    flash("Solicitud enviada. El administrador debe validarla.", "info")
    return redirect(url_for('perfil'))
# --- RUTA PARA EL ADMIN (ACEPTAR/NEGAR) ---
@app.route('/validar_entrega/<int:id_solicitud>/<accion>', methods=['POST'])
def validar_entrega(id_solicitud, accion):
    global solicitudes_pendientes
    
    # Buscamos la solicitud en la lista temporal
    solicitud = next((s for s in solicitudes_pendientes if s['id'] == id_solicitud), None)
    
    if solicitud:
        if accion == 'aceptar':
            # AQUÍ es donde se dan los puntos de verdad en la base de datos
            conn = get_db_connection()
            conn.execute("UPDATE users SET points = points + ? WHERE id = ?", 
                         (solicitud['puntos'], solicitud['user_id']))
            conn.commit()
            conn.close()
            flash(f"Entrega aprobada. Se otorgaron {solicitud['puntos']} puntos.", "success")
        else:
            flash("Entrega rechazada. No se otorgaron puntos.", "danger")

        # Quitamos la solicitud de la lista para que desaparezca de la tabla
        solicitudes_pendientes = [s for s in solicitudes_pendientes if s['id'] != id_solicitud]
    
    return redirect(url_for('admin_panel'))l
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user:
            if user['password'] == password or check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('interfaz'))
        
        return render_template('login.html', error='Usuario o contraseña incorrectos')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email'].lower().strip() # .strip() elimina espacios accidentales
        password = request.form['password']
        
        # 1. Definir estrictamente los dominios permitidos
        dominios_permitidos = ('@gmail.com', '@outlook.com', '@hotmail.com', '@live.com')
        
        # 2. VALIDACIÓN CRÍTICA: Si NO termina en uno de estos, se detiene
        if not email.endswith(dominios_permitidos):
            # Regresamos al template con un mensaje de error claro
            return render_template('register.html', error='Solo se permiten correos de Gmail, Outlook o Hotmail')

        # 3. Si pasó la validación anterior, procedemos con la base de datos
        conn = get_db_connection()
        try:
            # Verificar si el usuario o email ya existen para evitar errores de duplicado
            user_exists = conn.execute('SELECT id FROM users WHERE username = ? OR email = ?', 
                                     (username, email)).fetchone()
            if user_exists:
                flash('El nombre de usuario o el correo ya están registrados.', 'error')
                return render_template('register.html')

            # Encriptar contraseña e insertar
            hashed_pw = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, hashed_pw))
            conn.commit()
            flash('¡Cuenta creada con éxito! Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            return render_template('register.html', error=f'Error en la base de datos: {str(e)}')
        finally:
            conn.close()

    # Si es GET, simplemente mostramos la página limpia
    return render_template('register.html')
# --- RUTAS DE USUARIO ---

@app.route('/interfaz')
def interfaz():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    products = conn.execute('SELECT * FROM products WHERE active = 1').fetchall()
    conn.close()
    return render_template('interfaz.html', user=user, products=products)

@app.route('/cuenta')
def cuenta():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    canjes = conn.execute('''
        SELECT r.*, p.name as product_name 
        FROM redemptions r
        JOIN products p ON r.product_id = p.id
        WHERE r.user_id = ?
        ORDER BY r.date DESC LIMIT 10
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template(
        'cuenta.html',
        user_name=user['username'],
        user_email=user['email'],
        user_points=user['points'],
        canjes=canjes
    )

@app.route('/ganar_puntos', methods=['POST'])
def ganar_puntos():
    if 'user_id' in session:
        conn = get_db_connection()
        conn.execute('UPDATE users SET points = points + 10 WHERE id = ?', (session['user_id'],))
        conn.commit()
        conn.close()
        flash('¡Has ganado 10 puntos!', 'success')
        return redirect(url_for('cuenta'))
    return redirect(url_for('login'))

@app.route('/ubicaciones')
def ubicaciones():
    conn = get_db_connection()
    #   Obtenemos todos los materiales registrados
    materials = conn.execute('SELECT * FROM materials').fetchall()
    conn.close()
    # pasamos a la plantilla
    return render_template('ubicaciones.html', materials=materials)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- RUTAS DE ACCIÓN (Vender y Canjear) ---

@app.route('/vender', methods=['GET', 'POST'])
def vender():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            material_id = request.form.get('material_id')
            weight = float(request.form.get('weight'))
            
            conn = get_db_connection()
            material = conn.execute('SELECT * FROM materials WHERE id = ?', (material_id,)).fetchone()
            conn.close()

            if material and weight > 0:
                points_earned = int(material['points_per_kg'] * weight)
                
                # Guardamos en la lista global para que el admin lo vea
                nueva_solicitud = {
                    "id": len(solicitudes_pendientes) + 1,
                    "user_id": session['user_id'],
                    "username": session.get('username'),
                    "material": material['name'],
                    "puntos": points_earned,
                    "peso": weight
                }
                solicitudes_pendientes.append(nueva_solicitud)
                
                flash(f'Solicitud enviada. Espera a que el admin valide tus {weight}kg.', 'info')
                return redirect(url_for('admin_panel')) # O a tu perfil
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')

    # Para cargar la página vender.html
    conn = get_db_connection()
    materials = conn.execute('SELECT * FROM materials').fetchall()
    conn.close()
    return render_template('vender.html', materials=materials)

@app.route('/canje')
def canje():
    return redirect(url_for('interfaz'))

@app.route('/mis_canjes')
def mis_canjes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    canjes = conn.execute('''
        SELECT r.*, p.name as product_name, p.image
        FROM redemptions r
        JOIN products p ON r.product_id = p.id
        WHERE r.user_id = ?
        ORDER BY r.date DESC
    ''', (session['user_id'],)).fetchall()
    
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    conn.close()
    
    return render_template('mis_canjes.html', canjes=canjes, user=user)

@app.route('/canjear/<int:product_id>', methods=['POST'])
def canjear_producto(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    product = conn.execute(
        'SELECT * FROM products WHERE id = ? AND active = 1',
        (product_id,)
    ).fetchone()
    
    if not product:
        flash('Producto no disponible', 'error')
    elif user['points'] < product['points_cost']:
        flash(f'Faltan puntos. Costo: {product["points_cost"]}', 'error')
    elif product['stock'] <= 0:
        flash('Producto agotado', 'error')
    else:
        try:
            conn.execute(
                'UPDATE users SET points = points - ? WHERE id = ?',
                (product['points_cost'], session['user_id'])
            )
            conn.execute(
                'UPDATE products SET stock = stock - 1 WHERE id = ?',
                (product_id,)
            )
            conn.execute(
                'INSERT INTO redemptions (user_id, product_id, points_spent, status) VALUES (?, ?, ?, ?)',
                (session['user_id'], product_id, product['points_cost'], 'completado')
            )
            conn.commit()
            flash(f'¡Canje exitoso: {product["name"]}!', 'success')
        except Exception:
            conn.rollback()
            flash('Error en el canje', 'error')

    conn.close()
    return redirect(url_for('interfaz'))

@app.route('/delete_redemption/<int:id>', methods=['POST'])
@admin_required
def delete_redemption(id):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM redemptions WHERE id = ?', (id,))
        conn.commit()
        flash('Registro de canje eliminado', 'success')
    except Exception as e:
        flash(f'Error al eliminar: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_panel'))
# ========== RUTAS DE ADMINISTRADOR ==========

@app.route('/admin-login', methods=['GET', 'POST']) 
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        admin_user = conn.execute(
            'SELECT * FROM admins WHERE username = ?', (username,)
        ).fetchone()
        conn.close()

        if admin_user and check_password_hash(admin_user['password_hash'], password):
            session['admin_logged_in'] = True
            session['username'] = 'Administrador'
            return redirect(url_for('admin_panel'))
        elif username == "admin" and password == "admin123":
            session['admin_logged_in'] = True
            session['username'] = 'Administrador (Super)'
            return redirect(url_for('admin_panel'))
        else:
            return render_template('admin_login.html', error="Credenciales inválidas")
            
    return render_template('admin_login.html')

@app.route('/admin_panel')
@admin_required
def admin_panel():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    products = conn.execute('SELECT * FROM products').fetchall()
    materials = conn.execute('SELECT * FROM materials').fetchall()
    
    # Ventas de materiales
    sales_history = conn.execute('''
        SELECT s.*, u.username 
        FROM sales s 
        JOIN users u ON s.user_id = u.id 
        ORDER BY s.date DESC
    ''').fetchall()

    # Canjes de productos
    canjes = conn.execute('''
        SELECT r.*, u.username, p.name as product_name
        FROM redemptions r 
        JOIN users u ON r.user_id = u.id 
        JOIN products p ON r.product_id = p.id
        ORDER BY r.date DESC
    ''').fetchall()
    
    conn.close()
    
    # ✅ AGREGAMOS solicitudes=solicitudes_pendientes aquí:
    return render_template('admin_panel.html', 
                           users=users, 
                           products=products, 
                           materials=materials, 
                           sales_history=sales_history,
                           canjes=canjes,
                           solicitudes=solicitudes_pendientes) # <--- ¡ESTO ES LO QUE FALTA!

# --- Gestión de Materiales ---

@app.route('/add_material', methods=['POST'])
@admin_required
def add_material():
    name = request.form.get('name')
    points = request.form.get('points')
    requirements = request.form.get('requirements', '')
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO materials (name, points_per_kg, requirements) VALUES (?, ?, ?)',
        (name, points, requirements)
    )
    conn.commit()
    conn.close()
    flash('Material agregado')
    return redirect(url_for('admin_panel'))

@app.route('/delete_material/<int:id>', methods=['POST'])
@admin_required
def delete_material(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM materials WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Material eliminado')
    return redirect(url_for('admin_panel'))

# EDITAR MATERIAL COMPLETO
@app.route('/update_material/<int:id>', methods=['POST'])
@admin_required
def update_material(id):
    # Asegúrate de que estos nombres coincidan con el HTML
    name = request.form.get('name')
    points = request.form.get('points') # Antes tenías 'points_per_kg' aquí quizá
    requirements = request.form.get('requirements')
    
    # Validación básica para evitar que se envíen vacíos
    if not name or not points:
        flash('El nombre y los puntos son obligatorios', 'error')
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE materials 
            SET name = ?, points_per_kg = ?, requirements = ? 
            WHERE id = ?
        ''', (name, points, requirements, id))
        conn.commit()
        flash('Material actualizado con éxito', 'success')
    except Exception as e:
        flash(f'Error al actualizar: {str(e)}', 'error')
    finally:
        conn.close()
        
    return redirect(url_for('admin_panel'))

# --- Gestión de Productos  ---

@app.route('/add_product', methods=['POST'])
@admin_required
def add_product():
    name = request.form.get('name')
    cost = request.form.get('points_cost')
    stock = request.form.get('stock')
    image = request.form.get('image', 'default.png')
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO products (name, points_cost, stock, image) VALUES (?, ?, ?, ?)',
        (name, cost, stock, image)
    )
    conn.commit()
    conn.close()
    flash('Producto agregado al catálogo')
    return redirect(url_for('admin_panel'))

@app.route('/delete_product/<int:id>', methods=['POST'])
@admin_required
def delete_product(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM products WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Producto eliminado')
    return redirect(url_for('admin_panel'))

@app.route('/update_product/<int:id>', methods=['POST'])
@admin_required
def update_product(id):
    name = request.form.get('name')
    points_cost = request.form.get('points_cost')
    stock = request.form.get('stock')
    image = request.form.get('image')

    conn = get_db_connection()
    conn.execute(
        '''
        UPDATE products
        SET name = ?, points_cost = ?, stock = ?, image = ?
        WHERE id = ?
        ''',
        (name, points_cost, stock, image, id)
    )
    conn.commit()
    conn.close()
    flash('Producto actualizado')
    return redirect(url_for('admin_panel'))
# --- GESTIÓN DE USUARIOS (ADMIN) ---

@app.route('/update_user/<int:id>', methods=['POST'])
@admin_required
def update_user(id):
    username = request.form.get('username')
    email = request.form.get('email')
    points = request.form.get('points')
    new_password = request.form.get('password') # Nuevo campo
    
    conn = get_db_connection()
    
    # Actualizamos datos básicos
    conn.execute(
        'UPDATE users SET username = ?, email = ?, points = ? WHERE id = ?',
        (username, email, points, id)
    )
    
    # Si el admin escribió una nueva contraseña, la encriptamos y actualizamos
    if new_password and new_password.strip() != "":
        hashed_pw = generate_password_hash(new_password)
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pw, id))
    
    conn.commit()
    conn.close()
    flash('Usuario actualizado correctamente', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/delete_user/<int:id>', methods=['POST'])
@admin_required
def delete_user(id):
    conn = get_db_connection()
    # Eliminamos al usuario de la tabla users
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Usuario eliminado del sistema', 'danger')
    return redirect(url_for('admin_panel'))
# --- MAIN ---
if __name__ == '__main__':
    import os
    # Render asigna un puerto dinámico, esto lo detecta automáticamente
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)