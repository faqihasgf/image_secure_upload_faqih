import os
import uuid # For generating unique filenames
from flask import (
    Flask, request, redirect, url_for, render_template,
    flash, session, send_from_directory, abort
)
from werkzeug.utils import secure_filename # For sanitizing filenames
from werkzeug.security import generate_password_hash, check_password_hash # For password hashing

# --- Application Configuration ---
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}  # Allowed image file extensions
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB maximum file size

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['SECRET_KEY'] = os.urandom(24) # Strong secret key for session management

# --- In-Memory Data Storage ---
users_db = {} 
images_db = {}
user_next_id = 1
image_next_id = 1

# --- Helper Functions ---
def allowed_file(filename):
    # Checks if the file extension is allowed.
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_current_user_id():
    # Returns the user_id of the currently logged-in user, or None.
    return session.get('user_id')

def get_user_by_username(username):
    # Retrieves a user by username from the in-memory DB.
    for user_id, user_data in users_db.items():
        if user_data['username'] == username:
            return {'user_id': user_id, **user_data}
    return None

def get_user_by_id(user_id):
    # Retrieves a user by user_id from the in-memory DB.
    return users_db.get(user_id)

# --- Routes ---
@app.route('/')
def index():
    # Homepage: Redirects to gallery if logged in, else to login.
    if get_current_user_id():
        return redirect(url_for('gallery'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Handles user registration.
    global user_next_id
    if get_current_user_id(): # If already logged in, redirect to gallery
        return redirect(url_for('gallery'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')

        if get_user_by_username(username):
            flash('Username already exists. Please choose another.', 'error')
            return render_template('register.html')

        if len(password) < 6: # Basic password length validation
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        current_id = str(user_next_id)
        users_db[current_id] = {'username': username, 'password_hash': password_hash}
        user_next_id += 1
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Handles user login.
    if get_current_user_id(): # If already logged in, redirect to gallery
        return redirect(url_for('gallery'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        user_data_with_id = get_user_by_username(username)

        if user_data_with_id and check_password_hash(user_data_with_id['password_hash'], password):
            session['user_id'] = user_data_with_id['user_id']
            session['username'] = user_data_with_id['username'] # Store username for display
            flash('Logged in successfully!', 'success')
            # flash(users_db)
            return redirect(url_for('gallery'))
        else:
            flash('Invalid username or password.', 'error')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Handles user logout.
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_image():
    # Handles image upload.
    global image_next_id
    user_id = get_current_user_id()
    if not user_id:
        flash('Please log in to upload images.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in the request.', 'error')
            return redirect(request.url)
        
        file = request.files['file']

        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename) # Sanitize original filename
            extension = original_filename.rsplit('.', 1)[1].lower()
            # Generate a unique filename to prevent overwrites and path issues
            stored_filename = f"{uuid.uuid4()}.{extension}"
            
            # Create uploads folder if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                try:
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                except OSError as e:
                    app.logger.error(f"Error creating upload directory: {e}")
                    flash('Could not create upload directory on server.', 'error')
                    return redirect(request.url)
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
            
            try:
                file.save(file_path)
                # Store image metadata in our in-memory "DB"
                current_image_id = str(image_next_id)
                images_db[current_image_id] = {
                    'user_id': user_id,
                    'original_filename': original_filename,
                    'stored_filename': stored_filename,
                    'image_id': current_image_id
                }
                image_next_id += 1
                flash('Image uploaded successfully!', 'success')
                return redirect(url_for('gallery'))
            except Exception as e:
                app.logger.error(f"Error saving file: {e}")
                flash(f'An error occurred while saving the file: {e}', 'error')
                # Potentially remove partially saved file if necessary
                if os.path.exists(file_path):
                    os.remove(file_path)
                return redirect(request.url)
        else:
            flash(f'Invalid file type. Allowed types are: {", ".join(ALLOWED_EXTENSIONS)}.', 'error')
            return redirect(request.url)
            
    return render_template('upload.html')

@app.route('/gallery')
def gallery():
    # Displays the user's uploaded images.
    user_id = get_current_user_id()
    if not user_id:
        flash('Please log in to view your gallery.', 'error')
        return redirect(url_for('login'))

    user_images = []
    for img_id, img_data in images_db.items():
        if img_data['user_id'] == user_id:
            user_images.append(img_data)
    
    # Sort images using original filename
    user_images.sort(key=lambda x: x['original_filename'])
    
    return render_template('gallery.html', images=user_images)

@app.route('/image/<filename>')
def display_image(filename):
    # Serves an uploaded image file if the user is authorized.
    user_id = get_current_user_id()
    if not user_id:
        # Or redirect to login, or show a placeholder "access denied" image
        abort(401) # Unauthorized

    # Find the image by stored_filename and check ownership
    image_to_serve = None
    for img_data in images_db.values():
        if img_data['stored_filename'] == filename:
            if img_data['user_id'] == user_id:
                image_to_serve = img_data
                break
            else:
                # User is trying to access someone else's image
                abort(403) # Forbidden
    
    if not image_to_serve:
        abort(404) # Not Found

    # Securely send the file from the UPLOAD_FOLDER
    # send_from_directory handles security aspects like path traversal.
    return send_from_directory(app.config['UPLOAD_FOLDER'], image_to_serve['stored_filename'])

@app.route('/delete_image/<image_id>', methods=['POST'])
def delete_image(image_id):
    # Handles image deletion.
    user_id = get_current_user_id()
    if not user_id:
        flash('Please log in to delete images.', 'error')
        return redirect(url_for('login'))

    image_data = images_db.get(image_id)

    if not image_data:
        flash('Image not found.', 'error')
        return redirect(url_for('gallery'))

    if image_data['user_id'] != user_id:
        flash('You do not have permission to delete this image.', 'error')
        return redirect(url_for('gallery'))

    try:
        # Construct path to the image file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], image_data['stored_filename'])
        
        # Delete the image file from the filesystem
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete the image in-memory DB
        del images_db[image_id]
        
        flash('Image deleted successfully.', 'success')
    except OSError as e:
        app.logger.error(f"Error deleting image file {image_data['stored_filename']}: {e}")
        flash('Error deleting image file from server.', 'error')
    except KeyError:
        # This might happen if there's a race condition or data inconsistency
        app.logger.error(f"Error deleting image record for ID {image_id} from DB.")
        flash('Error deleting image record.', 'error')
        
    return redirect(url_for('gallery'))

# --- Error Handlers for common HTTP errors ---
@app.errorhandler(400) # Bad Request
@app.errorhandler(401) # Unauthorized
@app.errorhandler(403) # Forbidden
@app.errorhandler(404) # Not Found
@app.errorhandler(405) # Method Not Allowed
@app.errorhandler(500) # Internal Server Error
def handle_error(error):
    # Generic error handler.
    error_message = getattr(error, 'description', "An unexpected error occurred.")
    status_code = getattr(error, 'code', 500)
    
    # Log the error for debugging
    if status_code == 500:
        app.logger.error(f"Server Error {status_code}: {error_message} at {request.url}")
        
    return render_template('error.html', error_code=status_code, error_message=error_message), status_code


# Main 
if __name__ == '__main__':
    # Create the upload folder if it doesn't exist before starting the app
    if not os.path.exists(UPLOAD_FOLDER):
        try:
            os.makedirs(UPLOAD_FOLDER)
            print(f"Created upload folder: {UPLOAD_FOLDER}")
        except OSError as e:
            print(f"Error creating upload folder {UPLOAD_FOLDER}: {e}")
            # If error creating upload folder, show error and exit
            exit(1) 
            
    app.run(debug=True)
