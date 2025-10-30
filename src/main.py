"""
SecurePass Password Manager - Main Entry Point
Handles initial setup, login, and application launch
"""
import sys
from PyQt5.QtWidgets import (QApplication, QDialog, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QMessageBox,
                             QProgressBar)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from crypto_lib import CryptoManager
from db import DatabaseManager
from gui import MainWindow
from utils import PasswordStrengthChecker


class LoginWindow(QDialog):
    """Login/Setup window for master password"""

    def __init__(self):
        super().__init__()
        self.crypto = CryptoManager()
        self.db = DatabaseManager()
        self.setup_mode = self.db.get_config('salt') is None
        self.setup_ui()

    def setup_ui(self):
        """Initialize login UI"""
        self.setWindowTitle("SecurePass - Login")
        self.setFixedSize(450, 350)
        self.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowTitleHint)

        # Apply dark theme
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #e0e0e0;
                font-family: 'Segoe UI', Arial;
            }
            QLabel {
                color: #e0e0e0;
                font-size: 11pt;
            }
            QLineEdit {
                background-color: #2d2d2d;
                border: 2px solid #3d3d3d;
                border-radius: 6px;
                padding: 10px;
                color: #e0e0e0;
                font-size: 11pt;
            }
            QLineEdit:focus {
                border: 2px solid #0d7377;
            }
            QPushButton {
                background-color: #0d7377;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #14a085;
            }
            QPushButton:pressed {
                background-color: #0a5f63;
            }
            QProgressBar {
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                text-align: center;
                background-color: #2d2d2d;
                height: 20px;
            }
            QProgressBar::chunk {
                border-radius: 3px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)

        # Title
        title = QLabel("🔐 SecurePass")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Subtitle
        subtitle = QLabel("Master Password" if not self.setup_mode else "Create Master Password")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #999; font-size: 10pt;")
        layout.addWidget(subtitle)

        layout.addSpacing(20)

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter master password")
        self.password_input.returnPressed.connect(self.handle_login)
        layout.addWidget(self.password_input)

        if self.setup_mode:
            # Confirm password for setup
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            self.confirm_input.setPlaceholderText("Confirm master password")
            self.confirm_input.returnPressed.connect(self.handle_login)
            layout.addWidget(self.confirm_input)

            # Password strength indicator
            self.password_input.textChanged.connect(self.update_strength)
            self.strength_bar = QProgressBar()
            self.strength_bar.setMaximum(100)
            self.strength_label = QLabel("Password strength")
            self.strength_label.setStyleSheet("font-size: 9pt; color: #999;")
            layout.addWidget(self.strength_label)
            layout.addWidget(self.strength_bar)

            # Warning
            warning = QLabel("⚠️ Store this password securely!\nIt cannot be recovered if lost.")
            warning.setAlignment(Qt.AlignCenter)
            warning.setStyleSheet("color: #f39c12; font-size: 9pt; margin-top: 10px;")
            layout.addWidget(warning)

        layout.addSpacing(10)

        # Login/Create button
        btn_text = "Create Vault" if self.setup_mode else "Unlock Vault"
        self.login_btn = QPushButton(btn_text)
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)

        # Info text
        info_text = (
            "First time setup - creating encrypted vault"
            if self.setup_mode
            else "Enter your master password to unlock"
        )
        info = QLabel(info_text)
        info.setAlignment(Qt.AlignCenter)
        info.setStyleSheet("color: #666; font-size: 9pt;")
        layout.addWidget(info)

    def update_strength(self):
        """Update password strength indicator during setup"""
        if not self.setup_mode:
            return

        password = self.password_input.text()
        score, label, color = PasswordStrengthChecker.check_strength(password)
        self.strength_bar.setValue(score)
        self.strength_label.setText(f"Strength: {label}")
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")

    def handle_login(self):
        """Handle login or initial setup"""
        password = self.password_input.text()

        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password")
            return

        if self.setup_mode:
            # Initial setup
            confirm = self.confirm_input.text()
            if password != confirm:
                QMessageBox.warning(self, "Error", "Passwords do not match")
                return

            # Check password strength
            score, _, _ = PasswordStrengthChecker.check_strength(password)
            if score < 50:
                reply = QMessageBox.question(
                    self, "Weak Password",
                    "Your password is weak. Continue anyway?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            try:
                # Generate salt and derive key
                self.crypto.derive_key(password)

                # Store salt and iterations
                self.db.save_config('salt', self.crypto.get_salt_b64())
                self.db.save_config('iterations', str(CryptoManager.ITERATIONS))

                QMessageBox.information(
                    self, "Success",
                    "Vault created successfully!\n\nYou can now add your credentials."
                )

                self.launch_main_window()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Setup failed: {str(e)}")
        else:
            # Login with existing vault
            try:
                # Load salt
                salt_b64 = self.db.get_config('salt')
                self.crypto.set_salt_from_b64(salt_b64)

                # Derive key from password
                self.crypto.derive_key(password, self.crypto.salt)

                # Verify by attempting to decrypt a credential (if any exist)
                credentials = self.db.get_all_credentials()
                if credentials:
                    # Try to decrypt first credential as verification
                    try:
                        self.crypto.decrypt(credentials[0]['password_encrypted'])
                    except:
                        QMessageBox.critical(self, "Error", "Invalid master password")
                        return

                self.launch_main_window()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Login failed: {str(e)}")

    def launch_main_window(self):
        """Launch main application window"""
        self.main_window = MainWindow(self.crypto, self.db)
        self.main_window.show()
        self.accept()


def main():
    """Application entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look

    # Set application metadata
    app.setApplicationName("SecurePass")
    app.setOrganizationName("SecurePass")

    # Show login window
    login = LoginWindow()
    login.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
