import io
import pyotp
import qrcode
from flask import Flask, jsonify, request, send_file, session

app = Flask(__name__)
app.secret_key = "clave_ultra_segura_2FA"

# Simulación de base de datos
USERS = {
    "user@example.com": {
        "password": "1234",
        "secret": None  # se genera al activar el 2FA
    }
}

@app.route("/enable-2fa", methods=["POST"])
def enable_2fa():
    """Genera un secreto y un QR compatible con MS Authenticator"""
    data = request.json
    email = data.get("email")

    if email not in USERS:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Generar secreto único por usuario
    secret = pyotp.random_base32()
    USERS[email]["secret"] = secret

    # Crear URI estándar TOTP (compatible con MS Authenticator, Google Authenticator, etc.)
    totp_uri = pyotp.totp.TOTP(secret, interval=60).provisioning_uri(
        name=email,
        issuer_name="MiAppSegura"
    )

    # Generar QR en memoria
    qr_img = qrcode.make(totp_uri)
    img_bytes = io.BytesIO()
    qr_img.save(img_bytes, format="PNG")

    with open("qr.png", "wb") as qrfile:
        qrfile.write(img_bytes.read())
    img_bytes.seek(0)

    return send_file(img_bytes, mimetype="image/png")

@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    """Verifica el código 2FA introducido por el usuario"""
    data = request.json
    email = data.get("email")
    code = data.get("code")

    if email not in USERS or not USERS[email]["secret"]:
        return jsonify({"error": "2FA no configurado"}), 400

    totp = pyotp.TOTP(USERS[email]["secret"])

    # Verificar el código temporal (válido 30 segundos)
    if totp.verify(code):
        session["user"] = email
        return jsonify({"status": "ok", "message": "Código 2FA válido ✅"})
    else:
        return jsonify({"status": "error", "message": "Código incorrecto ❌"}), 401

@app.route("/login", methods=["POST"])
def login():
    """Simula el login de primer factor"""
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = USERS.get(email)
    if not user or user["password"] != password:
        return jsonify({"error": "Credenciales inválidas"}), 401

    # Si el usuario tiene 2FA activado, debe verificarse luego
    if user["secret"]:
        return jsonify({"2fa_required": True, "message": "Introduce el código 2FA"})
    else:
        session["user"] = email
        return jsonify({"status": "ok", "message": "Login sin 2FA"})

if __name__ == "__main__":
    app.run(debug=True)
