import base64
import io
import os
import random

from flask import Flask, redirect, render_template, request, url_for
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image

app = Flask(__name__)


 
# Configure JWT
app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)

CURRENT_TOKEN = None

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["5 per minute"],
)

# Routes


@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form.get('username', None)
    password = request.form.get('password', None)
  
    if not username or not password:
        return render_template('login.html', error='Enter username and password')
    if username != 'test' or password != 'test':
        return render_template('login.html', error='Invalid credentials')
    else:
        access_token = create_access_token(identity=username)
        CURRENT_TOKEN = access_token
        redir = redirect(url_for('uploadimage'))
        redir.set_cookie('access_token_cookie', access_token)
        redir.headers['Authorization'] = 'Bearer ' + access_token
        return redir

@app.route('/imageUpload')
def uploadimage():
    return render_template('uploadImage.html')

@app.route('/uploader', methods=['POST'])
@jwt_required()
def uploader():

    

    if 'image' not in request.files:
        return render_template('uploadImage.html', error='No image selected')

    image = request.files['image']
    if image.filename == '':
        return render_template('uploadImage.html', error='No image selected')

    upload_dir = 'static/uploads/'
    os.makedirs(upload_dir, exist_ok=True)
    image_data = request.files['image'].read()

    with open(os.path.join(upload_dir, image.filename), 'wb') as image_file:
        image_file.write(image_data)

    return { 'image_name': image.filename}


@app.route('/result')
def result():
    image = request.args.get('image', None)
    return render_template('result.html', image=image)

@app.route('/takeImage')
def capture():
    return render_template('capture.html')

@app.route('/storeBase64', methods=['POST'])
def storeBase64():
    data = request.get_json()
    img = data['img']
    upload_dir = 'static/uploads/'
    random_filename = 'image_' + str(random.randint(0, 100000)) + '.png'
   
    img = img.split(',')[1]

   
    image_bytes = base64.b64decode(img)
    image = Image.open(io.BytesIO(image_bytes))
    

    image.save(upload_dir + random_filename)

    return { 'image_name': random_filename}
    

@app.route('/logout')
def logout():
   
    redir = redirect(url_for('index'))
    redir.set_cookie('access_token_cookie', '', expires=0)
    return redir

@app.route('/testLimiter', methods=['GET'])
@limiter.limit("5 per minute")
def test_limiter():
    return 'You are under the rate limit'


if __name__ == '__main__':
    app.run(debug=True)
