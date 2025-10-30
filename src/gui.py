"""
PyQt5 GUI for SecurePass Password Manager
Main window with credential list, add/edit/delete, search, and settings
"""
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QPushButton, QLineEdit,
                             QDialog, QLabel, QFormLayout, QTextEdit, QMessageBox,
                             QComboBox, QCheckBox, QSpinBox, QProgressBar, QInputDialog,
                             QFileDialog, QHeaderView)
from PyQt5.QtCore import Qt, QTimer
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
        """Initialize UI components"""
        self.setWindowTitle("SecurePass - Password Manager")
        self.setGeometry(100, 100, 1000, 600)
        self.apply_dark_theme()
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Search bar
        search_layout = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 Search credentials...")
        self.search_box.textChanged.connect(self.search_credentials)
        search_layout.addWidget(self.search_box)
        
        lock_btn = QPushButton("🔒 Lock")
        lock_btn.clicked.connect(self.lock_vault)
        search_layout.addWidget(lock_btn)
        
        layout.addLayout(search_layout)
        
        # Credentials table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Service", "Username", "Category", "Modified", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)
        
        # Button bar
        btn_layout = QHBoxLayout()
        
        add_btn = QPushButton("➕ Add New")
        add_btn.clicked.connect(self.add_credential)
        btn_layout.addWidget(add_btn)
        
        edit_btn = QPushButton("✏️ Edit")
        edit_btn.clicked.connect(self.edit_credential)
        btn_layout.addWidget(edit_btn)
        
        delete_btn = QPushButton("🗑️ Delete")
        delete_btn.clicked.connect(self.delete_credential)
        btn_layout.addWidget(delete_btn)
        
        gen_btn = QPushButton("🎲 Generate Password")
        gen_btn.clicked.connect(self.show_generator)
        btn_layout.addWidget(gen_btn)
        
        export_btn = QPushButton("💾 Export")
        export_btn.clicked.connect(self.export_data)
        btn_layout.addWidget(export_btn)
        
        import_btn = QPushButton("📂 Import")
        import_btn.clicked.connect(self.import_data)
        btn_layout.addWidget(import_btn)
        
        layout.addLayout(btn_layout)
        
        # Status bar
        self.statusBar().showMessage("Ready | Auto-lock in 5 minutes")
    
    def apply_dark_theme(self):
        """Apply modern dark theme"""
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                font-family: 'Segoe UI', Arial;
                font-size: 10pt;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #2d2d2d;
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                padding: 6px;
                color: #e0e0e0;
            }
            QLineEdit:focus, QTextEdit:focus {
                border: 1px solid #0d7377;
            }
            QPushButton {
                background-color: #0d7377;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #14a085;
            }
            QPushButton:pressed {
                background-color: #0a5f63;
            }
            QTableWidget {
                background-color: #2d2d2d;
                alternate-background-color: #252525;
                gridline-color: #3d3d3d;
                border: 1px solid #3d3d3d;
            }
            QHeaderView::section {
                background-color: #1e1e1e;
                color: #e0e0e0;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #0d7377;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background-color: #0d7377;
            }
            QProgressBar {
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                text-align: center;
                background-color: #2d2d2d;
            }
            QProgressBar::chunk {
                border-radius: 3px;
            }
        """)
    
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
            self.statusBar().showMessage("✅ Credential added successfully", 3000)
    
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
                self.statusBar().showMessage("✅ Credential updated", 3000)
    
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
                self.statusBar().showMessage("✅ Credential deleted", 3000)
    
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
            self.statusBar().showMessage("📋 Password copied to clipboard (will clear in 30s)", 3000)
            
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
        """Setup dialog UI"""
        self.setWindowTitle("Add Credential" if self.mode == "add" else "Edit Credential")
        self.setModal(True)
        self.setMinimumWidth(500)
        
        layout = QFormLayout(self)
        
        self.service_edit = QLineEdit()
        layout.addRow("Service:", self.service_edit)
        
        self.username_edit = QLineEdit()
        layout.addRow("Username:", self.username_edit)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.textChanged.connect(self.update_strength)
        
        pw_layout = QHBoxLayout()
        pw_layout.addWidget(self.password_edit)
        
        show_btn = QPushButton("👁️")
        show_btn.setMaximumWidth(40)
        show_btn.pressed.connect(lambda: self.password_edit.setEchoMode(QLineEdit.Normal))
        show_btn.released.connect(lambda: self.password_edit.setEchoMode(QLineEdit.Password))
        pw_layout.addWidget(show_btn)
        
        gen_btn = QPushButton("🎲")
        gen_btn.setMaximumWidth(40)
        gen_btn.clicked.connect(self.generate_password)
        pw_layout.addWidget(gen_btn)
        
        layout.addRow("Password:", pw_layout)
        
        # Strength meter
        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(100)
        self.strength_label = QLabel("No password")
        strength_layout = QHBoxLayout()
        strength_layout.addWidget(self.strength_bar)
        strength_layout.addWidget(self.strength_label)
        layout.addRow("Strength:", strength_layout)
        
        self.url_edit = QLineEdit()
        layout.addRow("URL:", self.url_edit)
        
        self.category_combo = QComboBox()
        self.category_combo.addItems(["General", "Email", "Social", "Banking", "Work", "Shopping", "Other"])
        layout.addRow("Category:", self.category_combo)
        
        self.notes_edit = QTextEdit()
        self.notes_edit.setMaximumHeight(80)
        layout.addRow("Notes:", self.notes_edit)
        
        # Buttons
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("💾 Save")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addRow(btn_layout)
        
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
            self.category_combo.setCurrentText(self.credential.get('category', 'General'))
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
        """Update password strength indicator"""
        password = self.password_edit.text()
        score, label, color = PasswordStrengthChecker.check_strength(password)
        self.strength_bar.setValue(score)
        self.strength_label.setText(label)
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")
    
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
        """Setup generator UI"""
        self.setWindowTitle("Password Generator")
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setStyleSheet("font-size: 14pt; font-family: monospace;")
        layout.addWidget(self.password_display)
        
        # Options
        form = QFormLayout()
        
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(16)
        form.addRow("Length:", self.length_spin)
        
        self.upper_check = QCheckBox()
        self.upper_check.setChecked(True)
        form.addRow("Uppercase:", self.upper_check)
        
        self.lower_check = QCheckBox()
        self.lower_check.setChecked(True)
        form.addRow("Lowercase:", self.lower_check)
        
        self.digit_check = QCheckBox()
        self.digit_check.setChecked(True)
        form.addRow("Digits:", self.digit_check)
        
        self.symbol_check = QCheckBox()
        self.symbol_check.setChecked(True)
        form.addRow("Symbols:", self.symbol_check)
        
        layout.addLayout(form)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        gen_btn = QPushButton("🎲 Generate")
        gen_btn.clicked.connect(self.generate)
        btn_layout.addWidget(gen_btn)
        
        copy_btn = QPushButton("📋 Copy")
        copy_btn.clicked.connect(self.copy_password)
        btn_layout.addWidget(copy_btn)
        
        close_btn = QPushButton("✅ Close")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        
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
        """Copy generated password to clipboard"""
        pyperclip.copy(self.password_display.text())
        QMessageBox.information(self, "Copied", "Password copied to clipboard!")
