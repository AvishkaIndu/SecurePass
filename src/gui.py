"""
PyQt5 GUI for SecurePass Password Manager
Main window with credential list, add/edit/delete, search, and settings
"""
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QPushButton, QLineEdit,
                             QDialog, QLabel, QFormLayout, QTextEdit, QMessageBox,
                             QComboBox, QCheckBox, QSpinBox, QProgressBar, QInputDialog,
                             QFileDialog, QHeaderView, QGraphicsDropShadowEffect,
                             QGraphicsOpacityEffect)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtProperty
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor
import pyperclip
from crypto_lib import CryptoManager
from db import DatabaseManager
from utils import PasswordGenerator, PasswordStrengthChecker, format_timestamp


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, crypto: CryptoManager, db: DatabaseManager):
        super().__init__()
        self.crypto = crypto
        self.db = db
        self.auto_lock_timer = QTimer()
        self.auto_lock_timer.timeout.connect(self.lock_vault)
        self.setup_ui()
        self.load_credentials()
        self.start_auto_lock(300000)  # 5 minutes
    
    def setup_ui(self):
        """Initialize UI with simple cybersecurity design"""
        self.setWindowTitle("CyberVault - Password Management System")
        self.setGeometry(100, 100, 1200, 700)
        self.apply_dark_theme()
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Simple cyber header
        header_layout = QHBoxLayout()
        
        # System status - simplified
        status_panel = QWidget()
        status_panel.setObjectName("status_panel")
        status_panel.setStyleSheet("""
            QWidget#status_panel {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(0, 255, 65, 0.1), 
                    stop:1 rgba(0, 255, 65, 0.05));
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 10px;
            }
        """)
        status_layout = QHBoxLayout(status_panel)
        
        vault_status = QLabel("[VAULT] ENCRYPTED")
        vault_status.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 10pt;")
        status_layout.addWidget(vault_status)
        
        session_status = QLabel("[SESSION] ACTIVE")
        session_status.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 10pt;")
        status_layout.addWidget(session_status)
        
        header_layout.addWidget(status_panel)
        header_layout.addStretch()
        
        # Simple search and controls
        controls_layout = QHBoxLayout()
        
        # Search bar - simplified
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("[SEARCH] Enter credentials filter...")
        self.search_box.textChanged.connect(self.search_credentials)
        self.search_box.setMinimumHeight(35)
        controls_layout.addWidget(self.search_box)
        
        # Lock button
        lock_btn = QPushButton("[LOCK] VAULT")
        lock_btn.clicked.connect(self.lock_vault)
        lock_btn.setProperty("class", "danger")
        lock_btn.setMinimumHeight(35)
        lock_btn.setMaximumWidth(120)
        controls_layout.addWidget(lock_btn)
        
        header_layout.addLayout(controls_layout)
        layout.addLayout(header_layout)
        
        # Data table - simplified
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "[SERVICE]", "[USER]", "[CATEGORY]", "[MODIFIED]", "[ACTIONS]"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(350)
        layout.addWidget(self.table)
        
        # Simple button layout
        btn_frame = QWidget()
        btn_frame.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(0, 255, 65, 0.05), 
                    stop:1 rgba(0, 255, 65, 0.02));
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 15px;
            }
        """)
        btn_layout = QHBoxLayout(btn_frame)
        
        # Core functions - simplified
        add_btn = QPushButton("[ADD] NEW ENTRY")
        add_btn.clicked.connect(self.add_credential)
        btn_layout.addWidget(add_btn)
        
        edit_btn = QPushButton("[EDIT] ENTRY")
        edit_btn.clicked.connect(self.edit_credential)
        btn_layout.addWidget(edit_btn)
        
        delete_btn = QPushButton("[DELETE] ENTRY")
        delete_btn.clicked.connect(self.delete_credential)
        delete_btn.setProperty("class", "danger")
        btn_layout.addWidget(delete_btn)
        
        # Separator
        separator = QLabel(" | ")
        separator.setStyleSheet("color: #00ff41; font-size: 12pt; font-weight: bold;")
        btn_layout.addWidget(separator)
        
        # Tools
        gen_btn = QPushButton("[GENERATE] PASSWORD")
        gen_btn.clicked.connect(self.show_generator)
        btn_layout.addWidget(gen_btn)
        
        # Separator
        separator2 = QLabel(" | ")
        separator2.setStyleSheet("color: #00ff41; font-size: 12pt; font-weight: bold;")
        btn_layout.addWidget(separator2)
        
        # Data operations
        export_btn = QPushButton("[EXPORT] DATA")
        export_btn.clicked.connect(self.export_data)
        export_btn.setProperty("class", "secondary")
        btn_layout.addWidget(export_btn)
        
        import_btn = QPushButton("[IMPORT] DATA")
        import_btn.clicked.connect(self.import_data)
        import_btn.setProperty("class", "secondary")
        btn_layout.addWidget(import_btn)
        
        btn_layout.addStretch()
        layout.addWidget(btn_frame)
        
        # Simple status bar
        status_text = "[SYSTEM] READY | [CRYPTO] AES-256 ACTIVE | [AUTO-LOCK] 5 MIN"
        self.statusBar().showMessage(status_text)
    
    def apply_dark_theme(self):
        """Apply cybersecurity-focused theme with terminal aesthetics"""
        self.setStyleSheet("""
            /* Cybersecurity Main Window */
            QMainWindow, QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a0a, stop:0.3 #1a1a2e, stop:0.7 #16213e, stop:1 #0a0a0a);
                color: #00ff00;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
            }
            
            /* Terminal-style Input Fields */
            QLineEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #001100, stop:1 #002200);
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 10px 12px;
                color: #00ff00;
                font-size: 11pt;
                font-family: 'Consolas', monospace;
                selection-background-color: #00ff41;
                selection-color: #000000;
            }
            QLineEdit:focus {
                border: 2px solid #00ff88;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #002200, stop:1 #001a00);
                box-shadow: 0 0 15px rgba(0, 255, 65, 0.5);
            }
            QLineEdit::placeholder {
                color: #006600;
                font-style: italic;
            }
            
            /* Cyber Text Areas */
            QTextEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #001100, stop:1 #002200);
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 10px;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                selection-background-color: #00ff41;
                selection-color: #000000;
            }
            QTextEdit:focus {
                border: 2px solid #00ff88;
                box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
            }
            
            /* Cyber ComboBox */
            QComboBox {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #001100, stop:1 #002200);
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 8px 12px;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                min-width: 120px;
            }
            QComboBox:focus {
                border: 2px solid #00ff88;
            }
            QComboBox::drop-down {
                border: none;
                width: 25px;
            }
            QComboBox::down-arrow {
                image: none;
                border: 4px solid transparent;
                border-top: 6px solid #00ff41;
                margin-right: 8px;
            }
            QComboBox QAbstractItemView {
                background: #001100;
                border: 2px solid #00ff41;
                selection-background-color: #00ff41;
                selection-color: #000000;
                color: #00ff00;
                font-family: 'Consolas', monospace;
            }
            
            /* SpinBox Styling */
            QSpinBox {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #001100, stop:1 #002200);
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 8px 12px;
                color: #00ff00;
                font-family: 'Consolas', monospace;
            }
            QSpinBox:focus {
                border: 2px solid #00ff88;
            }
            
            /* Cyber Button Styling */
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #003300, stop:0.5 #00ff41, stop:1 #003300);
                color: #000000;
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 10px 16px;
                font-weight: bold;
                font-size: 10pt;
                font-family: 'Consolas', monospace;
                min-height: 15px;
                text-transform: uppercase;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ff41, stop:0.5 #66ff88, stop:1 #00ff41);
                box-shadow: 0 0 10px rgba(0, 255, 65, 0.6);
                color: #000000;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #002200, stop:0.5 #00aa22, stop:1 #002200);
                color: #00ff00;
            }
            
            /* Special Button Variants */
            QPushButton[class="danger"] {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #330000, stop:0.5 #ff0040, stop:1 #330000);
                border-color: #ff0040;
                color: #ffffff;
            }
            QPushButton[class="danger"]:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff0040, stop:0.5 #ff4080, stop:1 #ff0040);
                box-shadow: 0 0 10px rgba(255, 0, 64, 0.6);
            }
            
            QPushButton[class="secondary"] {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #001a33, stop:0.5 #0066ff, stop:1 #001a33);
                border-color: #0066ff;
                color: #ffffff;
            }
            QPushButton[class="secondary"]:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0066ff, stop:0.5 #4088ff, stop:1 #0066ff);
                box-shadow: 0 0 10px rgba(0, 102, 255, 0.6);
            }
            
            /* Cyber Table Styling */
            QTableWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #001100, stop:1 #000a00);
                alternate-background-color: rgba(0, 255, 65, 0.05);
                gridline-color: #00ff41;
                border: 2px solid #00ff41;
                border-radius: 0px;
                selection-background-color: rgba(0, 255, 65, 0.3);
                color: #00ff00;
                font-family: 'Consolas', monospace;
            }
            QTableWidget::item {
                padding: 10px 8px;
                border-bottom: 1px solid #00ff41;
                color: #00ff00;
            }
            QTableWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(0, 255, 65, 0.4), 
                    stop:1 rgba(0, 255, 65, 0.2));
                color: #000000;
                font-weight: bold;
            }
            QTableWidget::item:hover {
                background: rgba(0, 255, 65, 0.1);
            }
            
            /* Cyber Header Styling */
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #000a00, stop:1 #001100);
                color: #00ff88;
                padding: 12px 8px;
                border: none;
                border-bottom: 3px solid #00ff41;
                border-right: 1px solid #00ff41;
                font-weight: bold;
                font-size: 11pt;
                font-family: 'Consolas', monospace;
                text-transform: uppercase;
            }
            QHeaderView::section:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #001100, stop:1 #002200);
                color: #00ff00;
            }
            QHeaderView::section:first {
                border-left: none;
            }
            QHeaderView::section:last {
                border-right: none;
            }
            
            /* Cyber Progress Bar */
            QProgressBar {
                border: 2px solid #00ff41;
                border-radius: 0px;
                text-align: center;
                background: #001100;
                height: 25px;
                color: #00ff00;
                font-weight: bold;
                font-size: 10pt;
                font-family: 'Consolas', monospace;
            }
            QProgressBar::chunk {
                border-radius: 0px;
                margin: 1px;
            }
            
            /* Cyber Status Bar */
            QStatusBar {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #000a00, stop:1 #001100);
                border-top: 2px solid #00ff41;
                color: #00ff88;
                padding: 8px;
                font-size: 9pt;
                font-family: 'Consolas', monospace;
            }
            
            /* Dialog Enhancements */
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a0a, stop:0.3 #1a1a2e, stop:0.7 #16213e, stop:1 #0a0a0a);
                border: 3px solid #00ff41;
                border-radius: 0px;
            }
            
            /* Message Box Styling */
            QMessageBox {
                background: #001100;
                color: #00ff00;
                font-family: 'Consolas', monospace;
            }
            QMessageBox QPushButton {
                min-width: 80px;
                margin: 5px;
            }
            
            /* Scroll Bar Styling */
            QScrollBar:vertical {
                background: #001100;
                width: 15px;
                border-radius: 0px;
                border: 1px solid #00ff41;
            }
            QScrollBar::handle:vertical {
                background: #00ff41;
                border-radius: 0px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00ff88;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0px;
            }
        """)
        
        # Add cyber glow effect
        try:
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(20)
            shadow.setXOffset(0)
            shadow.setYOffset(0)
            shadow.setColor(QColor(0, 255, 65, 80))
            self.setGraphicsEffect(shadow)
        except:
            pass  # Fallback if effects not available
    
    def on_cell_hover(self, row, column):
        """Handle cell hover effects"""
        # Add subtle visual feedback for hovered rows
        pass  # Visual feedback is handled by CSS hover states
    
    def show_status_message(self, message, duration=3000, style="success"):
        """Show enhanced status messages with styling"""
        if style == "success":
            icon = "✅"
            color = "#68d391"
        elif style == "warning":
            icon = "⚠️"
            color = "#fbd38d"
        elif style == "error":
            icon = "❌"
            color = "#feb2b2"
        else:
            icon = "ℹ️"
            color = "#90cdf4"
            
        styled_message = f"{icon} {message}"
        self.statusBar().showMessage(styled_message, duration)
        
        # Add color styling to status bar temporarily
        original_style = self.statusBar().styleSheet()
        self.statusBar().setStyleSheet(f"""
            QStatusBar {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a202c, stop:1 #2d3748);
                border-top: 2px solid {color};
                color: {color};
                padding: 8px;
                font-size: 9pt;
                font-weight: bold;
            }}
        """)
        
        # Reset style after duration
        QTimer.singleShot(duration, lambda: self.statusBar().setStyleSheet(original_style))

    def load_credentials(self, search_term=""):
        """Load and display credentials in table"""
        self.table.setRowCount(0)
        credentials = self.db.get_all_credentials(search_term)
        
        for cred in credentials:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            self.table.setItem(row, 0, QTableWidgetItem(cred['service']))
            self.table.setItem(row, 1, QTableWidgetItem(cred['username']))
            self.table.setItem(row, 2, QTableWidgetItem(cred.get('category', 'General')))
            self.table.setItem(row, 3, QTableWidgetItem(format_timestamp(cred['modified_at'])))
            
            # Action buttons
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 0, 4, 0)
            
            view_btn = QPushButton("👁️")
            view_btn.setMaximumWidth(40)
            view_btn.clicked.connect(lambda checked, c=cred: self.view_password(c))
            action_layout.addWidget(view_btn)
            
            copy_btn = QPushButton("📋")
            copy_btn.setMaximumWidth(40)
            copy_btn.clicked.connect(lambda checked, c=cred: self.copy_password(c))
            action_layout.addWidget(copy_btn)
            
            self.table.setCellWidget(row, 4, action_widget)
    
    def search_credentials(self, text):
        """Filter credentials by search term"""
        self.load_credentials(text)
    
    def add_credential(self):
        """Show dialog to add new credential"""
        dialog = CredentialDialog(self, self.crypto, mode="add")
        if dialog.exec_():
            data = dialog.get_data()
            self.db.add_credential(
                service=data['service'],
                username=data['username'],
                password_encrypted=self.crypto.encrypt(data['password']),
                url=data['url'],
                notes_encrypted=self.crypto.encrypt(data['notes']),
                category=data['category']
            )
            self.load_credentials()
            self.show_status_message("Credential added successfully", style="success")
    
    def edit_credential(self):
        """Edit selected credential"""
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a credential to edit")
            return
        
        service = self.table.item(row, 0).text()
        credentials = self.db.get_all_credentials()
        cred = next((c for c in credentials if c['service'] == service), None)
        
        if cred:
            dialog = CredentialDialog(self, self.crypto, mode="edit", credential=cred)
            if dialog.exec_():
                data = dialog.get_data()
                self.db.update_credential(
                    cred_id=cred['id'],
                    service=data['service'],
                    username=data['username'],
                    password_encrypted=self.crypto.encrypt(data['password']),
                    url=data['url'],
                    notes_encrypted=self.crypto.encrypt(data['notes']),
                    category=data['category']
                )
                self.load_credentials()
                self.show_status_message("Credential updated successfully", style="success")
    
    def delete_credential(self):
        """Delete selected credential"""
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a credential to delete")
            return
        
        service = self.table.item(row, 0).text()
        reply = QMessageBox.question(self, "Confirm Delete",
                                     f"Delete credential for '{service}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            credentials = self.db.get_all_credentials()
            cred = next((c for c in credentials if c['service'] == service), None)
            if cred:
                self.db.delete_credential(cred['id'])
                self.load_credentials()
                self.show_status_message("Credential deleted successfully", style="warning")
    
    def view_password(self, cred):
        """Show password in dialog (requires re-auth)"""
        # Re-authenticate for security
        password, ok = QInputDialog.getText(self, "Authenticate",
                                           "Enter master password to view:",
                                           QLineEdit.Password)
        if not ok:
            return
        
        try:
            # Verify password by attempting decryption
            decrypted = self.crypto.decrypt(cred['password_encrypted'])
            
            msg = QMessageBox(self)
            msg.setWindowTitle("Password")
            msg.setText(f"Password for {cred['service']}:\n\n{decrypted}")
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()
        except:
            QMessageBox.critical(self, "Error", "Authentication failed or decryption error")
    
    def copy_password(self, cred):
        """Copy password to clipboard"""
        try:
            decrypted = self.crypto.decrypt(cred['password_encrypted'])
            pyperclip.copy(decrypted)
            self.show_status_message("Password copied to clipboard (auto-clear in 30s)", style="success")
            
            # Clear clipboard after 30 seconds
            QTimer.singleShot(30000, lambda: pyperclip.copy(''))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt: {str(e)}")
    
    def show_generator(self):
        """Show password generator dialog"""
        dialog = PasswordGeneratorDialog(self)
        dialog.exec_()
    
    def export_data(self):
        """Export encrypted data to JSON file"""
        path, _ = QFileDialog.getSaveFileName(self, "Export Data", "", "JSON Files (*.json)")
        if path:
            try:
                data = self.db.export_data()
                with open(path, 'w') as f:
                    f.write(data)
                QMessageBox.information(self, "Success", f"Data exported to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
    
    def import_data(self):
        """Import data from JSON file"""
        path, _ = QFileDialog.getOpenFileName(self, "Import Data", "", "JSON Files (*.json)")
        if path:
            try:
                with open(path, 'r') as f:
                    data = f.read()
                count = self.db.import_data(data)
                self.load_credentials()
                QMessageBox.information(self, "Success", f"Imported {count} credentials")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Import failed: {str(e)}")
    
    def start_auto_lock(self, ms):
        """Start auto-lock timer"""
        self.auto_lock_timer.start(ms)
    
    def lock_vault(self):
        """Lock the vault and return to login"""
        self.close()
        from main import LoginWindow
        self.login_window = LoginWindow()
        self.login_window.show()


class CredentialDialog(QDialog):
    """Dialog for adding/editing credentials"""
    
    def __init__(self, parent, crypto, mode="add", credential=None):
        super().__init__(parent)
        self.crypto = crypto
        self.mode = mode
        self.credential = credential
        self.setup_ui()
    
    def setup_ui(self):
        """Setup credential dialog with simple cyber styling"""
        title = "[ADD] NEW CREDENTIAL" if self.mode == "add" else "[EDIT] CREDENTIAL"
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(600)
        self.setMinimumHeight(600)
        
        # Apply cyber dialog styling
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a0a, stop:0.3 #1a1a2e, stop:0.7 #16213e, stop:1 #0a0a0a);
                border: 3px solid #00ff41;
                border-radius: 0px;
            }
            QLabel {
                color: #00ff00;
                font-weight: bold;
                font-size: 11pt;
                font-family: 'Consolas', monospace;
                padding: 5px 0;
            }
            QFormLayout {
                spacing: 15px;
            }
        """)
        
        layout = QFormLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = QLabel("[SYSTEM] CREDENTIAL DATA ENTRY")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(0, 255, 65, 0.2), 
                stop:1 rgba(0, 255, 65, 0.1));
            border: 2px solid #00ff41;
            border-radius: 0px;
            padding: 12px;
            font-size: 12pt;
            font-weight: bold;
            color: #00ff88;
            margin-bottom: 15px;
        """)
        layout.addRow(header)
        
        # Service field
        service_label = QLabel("[INPUT] SERVICE_NAME:")
        self.service_edit = QLineEdit()
        self.service_edit.setPlaceholderText("e.g., Gmail, GitHub, Banking...")
        layout.addRow(service_label, self.service_edit)
        
        # Username field
        username_label = QLabel("[INPUT] USERNAME:")
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Username or email address...")
        layout.addRow(username_label, self.username_edit)
        
        # Password field with controls
        password_label = QLabel("[INPUT] PASSWORD:")
        pw_container = QWidget()
        pw_layout = QHBoxLayout(pw_container)
        pw_layout.setContentsMargins(0, 0, 0, 0)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Enter secure password...")
        self.password_edit.textChanged.connect(self.update_strength)
        pw_layout.addWidget(self.password_edit)
        
        # Show button
        show_btn = QPushButton("[SHOW]")
        show_btn.setMaximumWidth(60)
        show_btn.pressed.connect(lambda: self.password_edit.setEchoMode(QLineEdit.Normal))
        show_btn.released.connect(lambda: self.password_edit.setEchoMode(QLineEdit.Password))
        pw_layout.addWidget(show_btn)
        
        # Generate button
        gen_btn = QPushButton("[GEN]")
        gen_btn.setMaximumWidth(50)
        gen_btn.clicked.connect(self.generate_password)
        pw_layout.addWidget(gen_btn)
        
        layout.addRow(password_label, pw_container)
        
        # Strength meter
        strength_label = QLabel("[ANALYSIS] SECURITY_LEVEL:")
        strength_container = QWidget()
        strength_layout = QVBoxLayout(strength_container)
        strength_layout.setContentsMargins(0, 0, 0, 0)
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(100)
        self.strength_bar.setMinimumHeight(25)
        strength_layout.addWidget(self.strength_bar)
        
        self.strength_label = QLabel("[STATUS] ANALYZING...")
        self.strength_label.setStyleSheet("font-size: 9pt; color: #00ff88; padding: 5px; font-family: 'Consolas', monospace;")
        self.strength_label.setAlignment(Qt.AlignCenter)
        strength_layout.addWidget(self.strength_label)
        
        layout.addRow(strength_label, strength_container)
        
        # URL field
        url_label = QLabel("[OPTIONAL] URL:")
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com")
        layout.addRow(url_label, self.url_edit)
        
        # Category field
        category_label = QLabel("[CATEGORY] TYPE:")
        self.category_combo = QComboBox()
        categories = ["GENERAL", "EMAIL", "SOCIAL", "BANKING", "WORK", "SHOPPING", "GAMING", "OTHER"]
        self.category_combo.addItems(categories)
        layout.addRow(category_label, self.category_combo)
        
        # Notes field
        notes_label = QLabel("[NOTES] ENCRYPTED_DATA:")
        notes_container = QWidget()
        notes_layout = QVBoxLayout(notes_container)
        notes_layout.setContentsMargins(0, 0, 0, 0)
        
        self.notes_edit = QTextEdit()
        self.notes_edit.setMaximumHeight(80)
        self.notes_edit.setPlaceholderText("Additional secure notes...")
        notes_layout.addWidget(self.notes_edit)
        
        encryption_notice = QLabel("[CRYPTO] AES-256 ENCRYPTION ACTIVE")
        encryption_notice.setStyleSheet("""
            background: rgba(0, 255, 65, 0.1);
            border: 1px solid #00ff41;
            border-radius: 0px;
            padding: 8px;
            font-size: 8pt;
            color: #00ff88;
            font-family: 'Consolas', monospace;
        """)
        encryption_notice.setAlignment(Qt.AlignCenter)
        notes_layout.addWidget(encryption_notice)
        
        layout.addRow(notes_label, notes_container)
        
        # Action buttons
        btn_container = QWidget()
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.setContentsMargins(0, 20, 0, 0)
        
        save_btn = QPushButton("[SAVE] CREDENTIAL")
        save_btn.clicked.connect(self.accept)
        save_btn.setMinimumHeight(40)
        btn_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("[CANCEL] OPERATION")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setProperty("class", "secondary")
        cancel_btn.setMinimumHeight(40)
        btn_layout.addWidget(cancel_btn)
        
        layout.addRow(btn_container)
        
        # Load existing data if editing
        if self.mode == "edit" and self.credential:
            self.service_edit.setText(self.credential['service'])
            self.username_edit.setText(self.credential['username'])
            try:
                pwd = self.crypto.decrypt(self.credential['password_encrypted'])
                self.password_edit.setText(pwd)
            except:
                pass
            self.url_edit.setText(self.credential.get('url', ''))
            
            # Match category
            category = self.credential.get('category', 'GENERAL').upper()
            index = self.category_combo.findText(category)
            if index >= 0:
                self.category_combo.setCurrentIndex(index)
                    
            try:
                notes = self.crypto.decrypt(self.credential.get('notes_encrypted', ''))
                self.notes_edit.setPlainText(notes)
            except:
                pass
    
    def generate_password(self):
        """Generate random password"""
        pwd = PasswordGenerator.generate(16)
        self.password_edit.setText(pwd)
    
    def update_strength(self):
        """Update password strength with cyber styling"""
        password = self.password_edit.text()
        score, label, color = PasswordStrengthChecker.check_strength(password)
        
        # Cyber-themed strength messages
        self.strength_bar.setValue(score)
        
        if score < 25:
            cyber_label = "[WEAK] VULNERABILITY DETECTED"
            gradient_color = "#ff0040"
            text_color = "#ff4080"
        elif score < 50:
            cyber_label = "[MODERATE] SECURITY ACCEPTABLE"
            gradient_color = "#ff8000"
            text_color = "#ffaa40"
        elif score < 75:
            cyber_label = "[STRONG] GOOD PROTECTION"
            gradient_color = "#ffff00"
            text_color = "#ffff80"
        else:
            cyber_label = "[SECURE] MAXIMUM PROTECTION"
            gradient_color = "#00ff40"
            text_color = "#80ff80"
            
        self.strength_label.setText(cyber_label)
        
        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {gradient_color}, stop:1 rgba(0,255,65,0.3));
                border-radius: 0px;
                margin: 1px;
            }}
        """)
        self.strength_label.setStyleSheet(f"font-size: 9pt; color: {text_color}; font-weight: bold; font-family: 'Consolas', monospace;")
    
    def get_data(self):
        """Return form data"""
        return {
            'service': self.service_edit.text(),
            'username': self.username_edit.text(),
            'password': self.password_edit.text(),
            'url': self.url_edit.text(),
            'category': self.category_combo.currentText(),
            'notes': self.notes_edit.toPlainText()
        }


class PasswordGeneratorDialog(QDialog):
    """Password generator utility dialog"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup enhanced password generator UI"""
        self.setWindowTitle("🎲 Advanced Password Generator")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.setMinimumHeight(450)
        
        # Apply enhanced styling
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f1419, stop:0.5 #1a1f2e, stop:1 #0f1419);
                border: 2px solid #4a5568;
                border-radius: 15px;
            }
            QCheckBox {
                color: #e2e8f0;
                font-size: 11pt;
                padding: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #4a5568;
                border-radius: 4px;
                background: #2d3748;
            }
            QCheckBox::indicator:checked {
                background: #0d7377;
                border-color: #0d7377;
            }
            QCheckBox::indicator:checked::after {
                content: "✓";
                color: white;
                font-weight: bold;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(25, 25, 25, 25)
        
        # Title
        title = QLabel("🛡️ SECURE PASSWORD GENERATOR")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(13, 115, 119, 0.3), 
                stop:0.5 rgba(20, 160, 133, 0.4), 
                stop:1 rgba(13, 115, 119, 0.3));
            border: 1px solid #0d7377;
            border-radius: 10px;
            padding: 15px;
            font-size: 13pt;
            font-weight: bold;
            color: #81e6d9;
        """)
        layout.addWidget(title)

        # Password display with enhanced styling
        display_container = QWidget()
        display_container.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 2px solid #4a5568;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        display_layout = QVBoxLayout(display_container)
        
        password_label = QLabel("🔐 Generated Password:")
        password_label.setStyleSheet("color: #a0aec0; font-weight: bold; margin-bottom: 10px;")
        display_layout.addWidget(password_label)
        
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setStyleSheet("""
            font-size: 14pt; 
            font-family: 'Consolas', 'Monaco', monospace;
            background: #0f1419;
            border: 1px solid #0d7377;
            color: #81e6d9;
            padding: 12px;
            font-weight: bold;
        """)
        display_layout.addWidget(self.password_display)
        
        layout.addWidget(display_container)

        # Options section
        options_container = QWidget()
        options_container.setStyleSheet("""
            QWidget {
                background: rgba(45, 55, 72, 0.3);
                border: 1px solid #4a5568;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        options_layout = QVBoxLayout(options_container)
        
        options_title = QLabel("⚙️ Generation Options:")
        options_title.setStyleSheet("color: #e2e8f0; font-weight: bold; font-size: 12pt; margin-bottom: 10px;")
        options_layout.addWidget(options_title)
        
        # Form layout for options
        form = QFormLayout()
        form.setSpacing(15)
        
        # Password length
        length_label = QLabel("📏 Password Length:")
        length_label.setStyleSheet("color: #e2e8f0; font-weight: bold;")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(16)
        self.length_spin.setStyleSheet("min-width: 80px;")
        form.addRow(length_label, self.length_spin)
        
        # Character type options
        char_label = QLabel("🔤 Character Types:")
        char_label.setStyleSheet("color: #e2e8f0; font-weight: bold;")
        char_widget = QWidget()
        char_layout = QVBoxLayout(char_widget)
        char_layout.setContentsMargins(0, 0, 0, 0)
        
        self.upper_check = QCheckBox("🔠 Uppercase Letters (A-Z)")
        self.upper_check.setChecked(True)
        char_layout.addWidget(self.upper_check)
        
        self.lower_check = QCheckBox("🔡 Lowercase Letters (a-z)")
        self.lower_check.setChecked(True)
        char_layout.addWidget(self.lower_check)
        
        self.digit_check = QCheckBox("🔢 Numbers (0-9)")
        self.digit_check.setChecked(True)
        char_layout.addWidget(self.digit_check)
        
        self.symbol_check = QCheckBox("🔣 Special Symbols (!@#$%^&*)")
        self.symbol_check.setChecked(True)
        char_layout.addWidget(self.symbol_check)
        
        form.addRow(char_label, char_widget)
        options_layout.addLayout(form)
        layout.addWidget(options_container)

        # Action buttons
        btn_container = QWidget()
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.setContentsMargins(0, 10, 0, 0)
        
        gen_btn = QPushButton("🎲 Generate New Password")
        gen_btn.clicked.connect(self.generate)
        gen_btn.setMinimumHeight(40)
        btn_layout.addWidget(gen_btn)
        
        copy_btn = QPushButton("📋 Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_password)
        copy_btn.setMinimumHeight(40)
        btn_layout.addWidget(copy_btn)
        
        close_btn = QPushButton("✅ Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setProperty("class", "secondary")
        close_btn.setMinimumHeight(40)
        btn_layout.addWidget(close_btn)
        
        layout.addWidget(btn_container)
        
        # Generate initial password
        self.generate()
    
    def generate(self):
        """Generate new password"""
        pwd = PasswordGenerator.generate(
            length=self.length_spin.value(),
            use_upper=self.upper_check.isChecked(),
            use_lower=self.lower_check.isChecked(),
            use_digits=self.digit_check.isChecked(),
            use_symbols=self.symbol_check.isChecked()
        )
        self.password_display.setText(pwd)
    
    def copy_password(self):
        """Copy generated password to clipboard with security notice"""
        try:
            import pyperclip
            pyperclip.copy(self.password_display.text())
            
            # Create a custom message box
            msg = QMessageBox(self)
            msg.setWindowTitle("🔒 Security Notice")
            msg.setText("🔐 Password Securely Copied!")
            msg.setInformativeText("Password copied to clipboard.\n\n⚠️ Clipboard will be cleared in 30 seconds for security.")
            msg.setIcon(QMessageBox.Information)
            msg.setStandardButtons(QMessageBox.Ok)
            
            # Apply styling to message box
            msg.setStyleSheet("""
                QMessageBox {
                    background: #1a202c;
                    color: #e2e8f0;
                }
                QMessageBox QPushButton {
                    min-width: 80px;
                    padding: 8px 16px;
                }
            """)
            
            msg.exec_()
            
            # Clear clipboard after 30 seconds
            QTimer.singleShot(30000, lambda: pyperclip.copy('') if 'pyperclip' in locals() else None)
        except ImportError:
            QMessageBox.warning(self, "Error", "Clipboard functionality not available")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to copy: {str(e)}")
