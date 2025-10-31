"""
SecurePass Password Manager - Main Entry Point
Handles initial setup, login, and application launch
"""
import sys
from PyQt5.QtWidgets import (QApplication, QDialog, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QMessageBox,
                             QProgressBar, QFrame, QGraphicsOpacityEffect,
                             QGraphicsDropShadowEffect, QGraphicsColorizeEffect)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtProperty, QSequentialAnimationGroup, QParallelAnimationGroup
from PyQt5.QtGui import QFont, QPalette, QLinearGradient, QBrush, QColor, QPainter
from crypto_lib import CryptoManager
from db import DatabaseManager
from gui import MainWindow
from utils import PasswordStrengthChecker


class CyberSecurityAnimator:
    """Handles cybersecurity-style animations for access control"""
    
    @staticmethod
    def create_access_denied_animation(parent, callback=None):
        """Create glitchy red 'ACCESS DENIED' animation"""
        # Create overlay label
        overlay = QLabel("🚫 ACCESS DENIED 🚫", parent)
        overlay.setAlignment(Qt.AlignCenter)
        overlay.setStyleSheet("""
            QLabel {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(220, 38, 127, 0.95), 
                    stop:0.5 rgba(239, 68, 68, 0.95), 
                    stop:1 rgba(220, 38, 127, 0.95));
                color: white;
                font-size: 22pt;
                font-weight: bold;
                font-family: 'Courier New', monospace;
                border: 3px solid #dc2626;
                border-radius: 15px;
                padding: 20px;
                letter-spacing: 3px;
            }
        """)
        overlay.setGeometry(parent.rect())
        overlay.show()
        
        # Create glitch animation sequence
        animation_group = QSequentialAnimationGroup()
        
        # Initial flash
        flash1 = QPropertyAnimation(overlay, b"opacity")
        flash1.setDuration(100)
        flash1.setStartValue(0.0)
        flash1.setEndValue(1.0)
        flash1.setEasingCurve(QEasingCurve.OutBounce)
        
        # Glitch effect (rapid opacity changes)
        for i in range(8):
            glitch = QPropertyAnimation(overlay, b"opacity")
            glitch.setDuration(50)
            glitch.setStartValue(1.0 if i % 2 == 0 else 0.3)
            glitch.setEndValue(0.3 if i % 2 == 0 else 1.0)
            animation_group.addAnimation(glitch)
        
        # Final fade out
        fade_out = QPropertyAnimation(overlay, b"opacity")
        fade_out.setDuration(800)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.0)
        fade_out.setEasingCurve(QEasingCurve.InQuad)
        
        animation_group.addAnimation(flash1)
        animation_group.addAnimation(fade_out)
        
        # Cleanup and callback
        def cleanup():
            overlay.deleteLater()
            if callback:
                callback()
        
        animation_group.finished.connect(cleanup)
        animation_group.start()
        
        return animation_group
    
    @staticmethod
    def create_access_granted_animation(parent, callback=None):
        """Create matrix-style green 'ACCESS GRANTED' animation"""
        # Create overlay label
        overlay = QLabel("✅ ACCESS GRANTED ✅", parent)
        overlay.setAlignment(Qt.AlignCenter)
        overlay.setStyleSheet("""
            QLabel {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(5, 150, 105, 0.95), 
                    stop:0.5 rgba(34, 197, 94, 0.95), 
                    stop:1 rgba(5, 150, 105, 0.95));
                color: white;
                font-size: 22pt;
                font-weight: bold;
                font-family: 'Courier New', monospace;
                border: 3px solid #059669;
                border-radius: 15px;
                padding: 20px;
                letter-spacing: 3px;
            }
        """)
        overlay.setGeometry(parent.rect())
        overlay.show()
        
        # Create matrix-style animation sequence
        animation_group = QSequentialAnimationGroup()
        
        # Matrix-style entrance (typing effect simulation)
        for i in range(5):
            flash = QPropertyAnimation(overlay, b"opacity")
            flash.setDuration(80)
            flash.setStartValue(0.0 if i == 0 else 0.7)
            flash.setEndValue(1.0)
            flash.setEasingCurve(QEasingCurve.OutQuad)
            animation_group.addAnimation(flash)
        
        # Hold for dramatic effect
        hold = QPropertyAnimation(overlay, b"opacity")
        hold.setDuration(1200)
        hold.setStartValue(1.0)
        hold.setEndValue(1.0)
        animation_group.addAnimation(hold)
        
        # Smooth fade out
        fade_out = QPropertyAnimation(overlay, b"opacity")
        fade_out.setDuration(600)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.0)
        fade_out.setEasingCurve(QEasingCurve.InQuad)
        animation_group.addAnimation(fade_out)
        
        # Cleanup and callback
        def cleanup():
            overlay.deleteLater()
            if callback:
                callback()
        
        animation_group.finished.connect(cleanup)
        animation_group.start()
        
        return animation_group


class AnimatedLabel(QLabel):
    """Custom label with fade animation effects"""
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._opacity = 1.0
        self.opacity_effect = QGraphicsOpacityEffect()
        self.setGraphicsEffect(self.opacity_effect)
        # Fix font display issues
        self.setMinimumHeight(30)
        self.setContentsMargins(4, 4, 4, 4)
        
    def get_opacity(self):
        return self._opacity
        
    def set_opacity(self, value):
        self._opacity = value
        self.opacity_effect.setOpacity(value)
        
    opacity = pyqtProperty(float, get_opacity, set_opacity)
    
    def fade_in(self, duration=500):
        """Animate fade in effect"""
        self.animation = QPropertyAnimation(self, b"opacity")
        self.animation.setDuration(duration)
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)
        self.animation.start()


class SecurityFrame(QFrame):
    """Custom frame with security-themed styling"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.NoFrame)
        # Fix layout issues
        self.setMinimumHeight(100)
        self.setContentsMargins(10, 10, 10, 10)
        
        # Add drop shadow effect
        try:
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(25)
            shadow.setXOffset(0)
            shadow.setYOffset(5)
            shadow.setColor(QColor(0, 0, 0, 80))
            self.setGraphicsEffect(shadow)
        except:
            pass  # Fallback if effects not available


class LoginWindow(QDialog):
    """Login/Setup window for master password"""

    def __init__(self):
        super().__init__()
        self.crypto = CryptoManager()
        self.db = DatabaseManager()
        self.setup_mode = self.db.get_config('salt') is None
        self.setup_ui()

    def setup_ui(self):
        """Initialize login UI with modern security-focused design"""
        self.setWindowTitle("SecurePass - Secure Authentication")
        self.setFixedSize(550, 650)
        self.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowTitleHint)

        # Apply modern security-themed dark theme
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f1419, stop:0.5 #1a1f2e, stop:1 #0f1419);
                color: #e0e6ed;
                font-family: 'Segoe UI', 'San Francisco', Arial;
                border: 2px solid #2d3748;
                border-radius: 15px;
            }
            QLabel {
                color: #e0e6ed;
                font-size: 12pt;
                background: transparent;
                padding: 8px 12px;
                line-height: 1.4;
                min-height: 20px;
            }
            QLineEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 2px solid #4a5568;
                border-radius: 10px;
                padding: 18px 24px;
                color: #e0e6ed;
                font-size: 13pt;
                selection-background-color: #0d7377;
                min-height: 24px;
                line-height: 1.3;
            }
            QLineEdit:focus {
                border: 2px solid #0d7377;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0d7377, stop:0.1 #2d3748, stop:1 #1a202c);
                box-shadow: 0 0 20px rgba(13, 115, 119, 0.3);
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0d7377, stop:0.5 #14a085, stop:1 #0d7377);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 18px 30px;
                font-weight: bold;
                font-size: 14pt;
                min-height: 25px;
                line-height: 1.2;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #14a085, stop:0.5 #17c4a5, stop:1 #14a085);
                transform: translateY(-2px);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0a5f63, stop:0.5 #0d7377, stop:1 #0a5f63);
                transform: translateY(1px);
            }
            QProgressBar {
                border: 2px solid #4a5568;
                border-radius: 8px;
                text-align: center;
                background: #1a202c;
                height: 30px;
                color: white;
                font-weight: bold;
                font-size: 11pt;
                padding: 4px;
            }
            QProgressBar::chunk {
                border-radius: 6px;
                margin: 2px;
            }
            QFrame#security_frame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(45, 55, 72, 0.8), 
                    stop:0.5 rgba(26, 32, 44, 0.9), 
                    stop:1 rgba(45, 55, 72, 0.8));
                border: 1px solid #4a5568;
                border-radius: 15px;
                padding: 25px;
            }
        """)

        # Main layout with proper spacing
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(30)
        main_layout.setContentsMargins(45, 45, 45, 45)

        # Security frame container
        security_frame = SecurityFrame()
        security_frame.setObjectName("security_frame")
        frame_layout = QVBoxLayout(security_frame)
        frame_layout.setSpacing(20)
        frame_layout.setContentsMargins(30, 30, 30, 30)

        # Animated title with security icon
        title_container = QVBoxLayout()
        title_container.setSpacing(15)
        
        self.title = AnimatedLabel("🛡️ SecurePass")
        self.title.setAlignment(Qt.AlignCenter)
        title_font = QFont("Segoe UI", 26, QFont.Bold)
        self.title.setFont(title_font)
        self.title.setMinimumHeight(50)
        self.title.setStyleSheet("""
            color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #0d7377, stop:0.5 #14a085, stop:1 #0d7377);
            padding: 15px;
            margin: 10px;
        """)
        title_container.addWidget(self.title)
        
        # Animated subtitle
        subtitle_text = "Professional Password Management" if not self.setup_mode else "Vault Initialization"
        self.subtitle = AnimatedLabel(subtitle_text)
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.subtitle.setMinimumHeight(35)
        self.subtitle.setStyleSheet("""
            color: #a0aec0; 
            font-size: 12pt; 
            font-weight: 300;
            padding: 10px;
            margin: 5px;
        """)
        title_container.addWidget(self.subtitle)
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.subtitle.setStyleSheet("""
            color: #a0aec0; 
            font-size: 11pt; 
            font-weight: 300;
            padding: 5px;
        """)
        title_container.addWidget(self.subtitle)
        
        frame_layout.addLayout(title_container)
        frame_layout.addSpacing(15)

        # Security status indicator
        self.security_status = AnimatedLabel("🔒 Encrypted • 🔐 Secure • 🛡️ Protected")
        self.security_status.setAlignment(Qt.AlignCenter)
        self.security_status.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(13, 115, 119, 0.2), 
                stop:0.5 rgba(20, 160, 133, 0.3), 
                stop:1 rgba(13, 115, 119, 0.2));
            border: 1px solid #0d7377;
            border-radius: 20px;
            padding: 10px;
            font-size: 10pt;
            color: #81e6d9;
        """)
        frame_layout.addWidget(self.security_status)
        frame_layout.addSpacing(10)

        # Password input section
        input_section = QVBoxLayout()
        input_section.setSpacing(15)

        # Master password label
        password_label = QLabel("🔑 Master Password")
        password_label.setStyleSheet("font-weight: bold; font-size: 11pt; color: #e0e6ed;")
        input_section.addWidget(password_label)

        # Password input with icon
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your secure master password...")
        self.password_input.returnPressed.connect(self.handle_login)
        input_section.addWidget(self.password_input)

        if self.setup_mode:
            # Confirm password for setup
            confirm_label = QLabel("🔒 Confirm Password")
            confirm_label.setStyleSheet("font-weight: bold; font-size: 11pt; color: #e0e6ed;")
            input_section.addWidget(confirm_label)
            
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            self.confirm_input.setPlaceholderText("Re-enter password to confirm...")
            self.confirm_input.returnPressed.connect(self.handle_login)
            input_section.addWidget(self.confirm_input)

            # Password strength indicator with enhanced styling
            self.password_input.textChanged.connect(self.update_strength)
            
            strength_label = QLabel("🎯 Password Strength")
            strength_label.setStyleSheet("font-weight: bold; font-size: 10pt; color: #a0aec0;")
            input_section.addWidget(strength_label)
            
            self.strength_bar = QProgressBar()
            self.strength_bar.setMaximum(100)
            input_section.addWidget(self.strength_bar)
            
            self.strength_label = QLabel("Enter password to check strength")
            self.strength_label.setStyleSheet("font-size: 9pt; color: #718096; text-align: center;")
            self.strength_label.setAlignment(Qt.AlignCenter)
            input_section.addWidget(self.strength_label)

            # Security warning with enhanced styling
            warning = QLabel("⚠️ CRITICAL SECURITY NOTICE")
            warning.setAlignment(Qt.AlignCenter)
            warning.setStyleSheet("""
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(245, 101, 101, 0.2), 
                    stop:1 rgba(246, 173, 85, 0.2));
                border: 1px solid #f56565;
                border-radius: 8px;
                padding: 15px;
                color: #feb2b2;
                font-size: 10pt;
                font-weight: bold;
                margin: 10px 0;
            """)
            input_section.addWidget(warning)
            
            warning_detail = QLabel("Your master password cannot be recovered if lost.\nStore it in a secure location.")
            warning_detail.setAlignment(Qt.AlignCenter)
            warning_detail.setStyleSheet("color: #fbb6ce; font-size: 9pt; padding: 5px;")
            input_section.addWidget(warning_detail)

        frame_layout.addLayout(input_section)
        frame_layout.addSpacing(15)

        # Action button
        btn_text = "🛡️ Create Secure Vault" if self.setup_mode else "🔓 Unlock Vault"
        self.login_btn = QPushButton(btn_text)
        self.login_btn.clicked.connect(self.handle_login)
        self.login_btn.setMinimumHeight(50)
        frame_layout.addWidget(self.login_btn)

        # Info section
        info_text = (
            "🔐 Initializing encrypted vault with AES-256 encryption"
            if self.setup_mode
            else "🔑 Enter master password to decrypt your secure vault"
        )
        self.info_label = AnimatedLabel(info_text)
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setStyleSheet("""
            background: rgba(74, 85, 104, 0.3);
            border: 1px solid #4a5568;
            border-radius: 8px;
            padding: 12px;
            color: #a0aec0;
            font-size: 9pt;
        """)
        frame_layout.addWidget(self.info_label)

        main_layout.addWidget(security_frame)
        
        # Start entrance animations
        QTimer.singleShot(100, self.animate_entrance)

    def animate_entrance(self):
        """Animate the entrance of UI elements"""
        self.title.fade_in(800)
        QTimer.singleShot(200, lambda: self.subtitle.fade_in(600))
        QTimer.singleShot(400, lambda: self.security_status.fade_in(500))
        QTimer.singleShot(600, lambda: self.info_label.fade_in(400))

    def update_strength(self):
        """Update password strength indicator with enhanced styling"""
        if not self.setup_mode:
            return

        password = self.password_input.text()
        score, label, color = PasswordStrengthChecker.check_strength(password)
        
        # Enhanced strength bar styling
        self.strength_bar.setValue(score)
        self.strength_label.setText(f"🎯 Strength: {label}")
        
        # Color gradient based on strength
        if score < 25:
            gradient_color = "#f56565"  # Red
            text_color = "#feb2b2"
        elif score < 50:
            gradient_color = "#ed8936"  # Orange
            text_color = "#fbd38d"
        elif score < 75:
            gradient_color = "#ecc94b"  # Yellow
            text_color = "#f6e05e"
        else:
            gradient_color = "#48bb78"  # Green
            text_color = "#9ae6b4"
            
        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {gradient_color}, stop:1 rgba(255,255,255,0.3));
                border-radius: 6px;
                margin: 1px;
            }}
        """)
        self.strength_label.setStyleSheet(f"font-size: 9pt; color: {text_color}; font-weight: bold;")

    def handle_login(self):
        """Handle login or initial setup with cyber security animations"""
        password = self.password_input.text()

        if not password:
            # Show cyber-style warning for empty password
            CyberSecurityAnimator.create_access_denied_animation(self)
            return

        if self.setup_mode:
            # Initial setup
            confirm = self.confirm_input.text()
            if password != confirm:
                # Show access denied animation for password mismatch
                CyberSecurityAnimator.create_access_denied_animation(self)
                return

            # Check password strength
            score, _, _ = PasswordStrengthChecker.check_strength(password)
            if score < 50:
                reply = QMessageBox.question(
                    self, "⚠️ Weak Password Detected",
                    "🔒 Security Alert: Your password strength is below recommended levels.\n\nContinue with weak password?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            try:
                # Show processing animation
                self.login_btn.setText("🔐 Creating Secure Vault...")
                self.login_btn.setEnabled(False)
                
                # Generate salt and derive key
                self.crypto.derive_key(password)

                # Store salt and iterations
                self.db.save_config('salt', self.crypto.get_salt_b64())
                self.db.save_config('iterations', str(CryptoManager.ITERATIONS))

                # Show access granted animation
                def on_success_complete():
                    self.launch_main_window()
                
                CyberSecurityAnimator.create_access_granted_animation(self, on_success_complete)
                
            except Exception as e:
                self.login_btn.setText("🛡️ Create Secure Vault")
                self.login_btn.setEnabled(True)
                CyberSecurityAnimator.create_access_denied_animation(self)
        else:
            # Login with existing vault
            try:
                # Show processing state
                self.login_btn.setText("🔓 Authenticating...")
                self.login_btn.setEnabled(False)
                
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
                        # Show cyber-style access denied animation
                        self.login_btn.setText("🔓 Unlock Vault")
                        self.login_btn.setEnabled(True)
                        CyberSecurityAnimator.create_access_denied_animation(self)
                        return

                # Show access granted animation and proceed
                def on_login_complete():
                    self.launch_main_window()
                
                CyberSecurityAnimator.create_access_granted_animation(self, on_login_complete)
                
            except Exception as e:
                self.login_btn.setText("🔓 Unlock Vault")
                self.login_btn.setEnabled(True)
                CyberSecurityAnimator.create_access_denied_animation(self)

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
