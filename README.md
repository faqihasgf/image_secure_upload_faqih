# Secure Image Upload

This is a web application that allows users to securely register, log in, upload image files, view them in a personalized gallery, and delete them.

## Features

* **User Authentication:** Secure registration and login system with password hashing.
* **Secure Image Upload:**
    * Validates file types (supports `.png`, `.jpg`, `.jpeg`).
    * Enforces maximum file size (5MB).
    * Uses secure filenames on the server to prevent conflicts and path traversal issues.
* **Personalized Image Gallery:** Logged-in users can view only their uploaded images.
* **Image Deletion:** Users can delete their images.
* **User Feedback:** Interactive messages for successful operations and errors.
* **Responsive Design:** Styled with Tailwind CSS for a good experience on various devices.

## Project Structure


```
image_secure_upload_faqih/
├── app.py             # Main Flask application logic
├── templates/         # HTML 
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── upload.html
│   ├── gallery.html
│   └── error.html
├── static/            # Static files (CSS)
│   └── style.css      # (Tailwind CSS)
├── uploads/           # Directory where uploaded images are stored (auto-created)
├── requirement.txt    # Python dependencies
└── README.md          # This file
```

## Setup and Installation

1.  **Prerequisites:**
    * Python 3.7+
    * `pip` (Python package installer)
    * A virtual environment tool (e.g., `venv`) is highly recommended.

2.  **Clone the Repository:**

        git clone <repository_url>
        cd image_secure_upload_faqih
        
    * Otherwise, create the directory structure and files as listed above.

3.  **Create and Activate a Virtual Environment:**
    
    ```python -m venv venv```

4.  **Install Dependencies:**
    
    ```pip install -r requirements.txtv```
    

5.  **Run the Application:**
    
    ```python app.py```
    
    /the application will typically be available at `http://127.0.0.1:5000/`. The `uploads/` directory will be created automatically if it doesn't exist when the app starts./

## Design Rationale & Assumptions

* **Framework:** Flask was chosen for its simplicity and flexibility, making it suitable for this project's scale.
* **Frontend:** HTML with Tailwind CSS (via CDN) is used for rapid UI development and responsiveness.
* **Data Storage:** For this simplycity, user and image metadata are stored in **in-memory Python dictionaries**.
    * **IMPORTANT ASSUMPTION:** This means all data (user accounts, uploaded image records, and the files themselves  will be lost when the Flask server restarts. 
* **Security:**
    * Passwords are hashed using `werkzeug.security.generate_password_hash`.
    * Filenames are sanitized using `werkzeug.utils.secure_filename`, and unique UUID-based names are used for storage to prevent conflicts and improve security.
    * File uploads are validated for allowed extensions and maximum size.
    * Image access is restricted: users can only view and delete their own images.
    * A strong `SECRET_KEY` is generated on startup for session management.
* **User Experience:** Flashed messages provide immediate feedback for user actions. Basic error pages are included.

## Test
* The web application has undergone comprehensive manual testing across all features and is functioning as expected.
