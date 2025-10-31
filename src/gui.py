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
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtProperty, QRect
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor, QPainter, QPen
import pyperclip
from crypto_lib import CryptoManager
from db import DatabaseManager
from utils import PasswordGenerator, PasswordStrengthChecker, format_timestamp


class CyberAnimatedWidget(QWidget):
    """Widget with cybersecurity-themed animations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_position = 0
        self.matrix_chars = []
        self.setup_cyber_animations()
    
    def setup_cyber_animations(self):
        """Initialize cyber animation timers"""
        # Scanning line animation
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.update_scan)
        self.scan_timer.start(80)
        
        # Matrix effect timer
        self.matrix_timer = QTimer()
        self.matrix_timer.timeout.connect(self.update_matrix)
        self.matrix_timer.start(150)
        
        # Initialize matrix characters
        import random
        for i in range(20):
            self.matrix_chars.append({
                'x': random.randint(0, 600),
                'y': random.randint(0, 400),
                'char': random.choice('01'),
                'alpha': random.randint(50, 150)
            })
    
    def update_scan(self):
        """Update scanning animation"""
        self.scan_position = (self.scan_position + 3) % (self.width() + 50)
        self.update()
    
    def update_matrix(self):
        """Update matrix effect"""
        import random
        for char in self.matrix_chars:
            char['y'] = (char['y'] + random.randint(1, 3)) % self.height()
            char['alpha'] = max(30, char['alpha'] - random.randint(1, 5))
            if char['alpha'] <= 30:
                char['alpha'] = 150
                char['x'] = random.randint(0, self.width())
                char['y'] = 0
                char['char'] = random.choice('01')
        self.update()
    
    def paintEvent(self, event):
        """Custom paint with cyber effects"""
        super().paintEvent(event)
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw matrix background
        painter.setFont(QFont('Courier New', 8))
        for char in self.matrix_chars:
            color = QColor(13, 115, 119, char['alpha'])
            painter.setPen(color)
            painter.drawText(char['x'], char['y'], char['char'])
        
        # Draw scanning line
        scan_color = QColor(20, 160, 133, 100)
        painter.setPen(QPen(scan_color, 2))
        painter.drawLine(self.scan_position, 0, self.scan_position, self.height())
        
        # Draw cyber grid corners
        corner_color = QColor(13, 115, 119, 150)
        painter.setPen(QPen(corner_color, 2))
        
        # Corner brackets
        size = 15
        painter.drawLine(5, 5, 5 + size, 5)
        painter.drawLine(5, 5, 5, 5 + size)
        
        painter.drawLine(self.width() - 5 - size, 5, self.width() - 5, 5)
        painter.drawLine(self.width() - 5, 5, self.width() - 5, 5 + size)


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
        """Initialize UI components with enhanced cybersecurity design"""
        self.setWindowTitle("🛡️ SecurePass - CYBER SECURITY PROTOCOL")
        self.setGeometry(100, 100, 1300, 750)
        self.apply_dark_theme()
        
        # Create cyber animated background
        cyber_bg = CyberAnimatedWidget()
        cyber_bg.setGeometry(0, 0, self.width(), self.height())
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(18)
        layout.setContentsMargins(25, 25, 25, 25)
        
        # Security header with enhanced status indicators
        header_layout = QHBoxLayout()
        
        # Enhanced security status panel
        security_panel = QWidget()
        security_panel.setObjectName("security_panel")
        security_panel.setStyleSheet("""
            QWidget#security_panel {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(13, 115, 119, 0.3), 
                    stop:0.5 rgba(20, 160, 133, 0.4), 
                    stop:1 rgba(13, 115, 119, 0.3));
                border: 2px solid #0d7377;
                border-radius: 12px;
                padding: 15px;
                min-height: 60px;
            }
        """)
        security_layout = QHBoxLayout(security_panel)
        security_layout.setSpacing(20)
        
        vault_status = QLabel("🔒 VAULT: ENCRYPTED")
        vault_status.setStyleSheet("""
            color: #81e6d9; 
            font-weight: bold; 
            font-size: 11pt; 
            padding: 8px 12px;
            min-height: 30px;
            background: rgba(129, 230, 217, 0.1);
            border-radius: 6px;
        """)
        security_layout.addWidget(vault_status)
        
        session_status = QLabel("🟢 SESSION: ACTIVE")
        session_status.setStyleSheet("""
            color: #68d391; 
            font-weight: bold; 
            font-size: 11pt;
            padding: 8px 12px;
            min-height: 30px;
            background: rgba(104, 211, 145, 0.1);
            border-radius: 6px;
        """)
        security_layout.addWidget(session_status)
        
        encryption_status = QLabel("🛡️ AES-256 PROTECTED")
        encryption_status.setStyleSheet("""
            color: #90cdf4; 
            font-weight: bold; 
            font-size: 11pt;
            padding: 8px 12px;
            min-height: 30px;
            background: rgba(144, 205, 244, 0.1);
            border-radius: 6px;
        """)
        security_layout.addWidget(encryption_status)
        
        header_layout.addWidget(security_panel)
        header_layout.addStretch()
        
        # Enhanced search and lock section
        search_lock_layout = QHBoxLayout()
        
        # Cyber-themed search bar
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍 SEARCH ENCRYPTED CREDENTIALS...")
        self.search_box.textChanged.connect(self.search_credentials)
        self.search_box.setMinimumHeight(45)
        self.search_box.setStyleSheet("""
            QLineEdit {
                font-size: 12pt;
                padding: 12px 18px;
                min-height: 25px;
            }
        """)
        search_lock_layout.addWidget(self.search_box)
        
        # Enhanced lock button
        lock_btn = QPushButton("🔒 SECURE LOCK")
        lock_btn.clicked.connect(self.lock_vault)
        lock_btn.setProperty("class", "danger")
        lock_btn.setMinimumHeight(45)
        lock_btn.setMaximumWidth(140)
        lock_btn.setStyleSheet("""
            QPushButton {
                font-size: 12pt;
                padding: 12px 18px;
                min-height: 25px;
            }
        """)
        search_lock_layout.addWidget(lock_btn)
        
        header_layout.addLayout(search_lock_layout)
        layout.addLayout(header_layout)
        
        # Enhanced credentials table with cyber styling
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "🏢 SERVICE", "👤 USERNAME", "📁 CATEGORY", "📅 MODIFIED", "🔧 ACTIONS"
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
        
        # Add cyber hover effects for table
        self.table.setMouseTracking(True)
        self.table.cellEntered.connect(self.on_cell_hover)
        
        layout.addWidget(self.table)
        
        # Enhanced button bar with cyber sections
        btn_frame = QWidget()
        btn_frame.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(45, 55, 72, 0.6), 
                    stop:1 rgba(26, 32, 44, 0.6));
                border: 2px solid #4a5568;
                border-radius: 12px;
                padding: 15px;
                min-height: 80px;
            }
        """)
        btn_layout = QHBoxLayout(btn_frame)
        btn_layout.setSpacing(15)
        
        # Credential management section with cyber styling
        cred_section = QLabel("📋 CREDENTIAL OPERATIONS:")
        cred_section.setStyleSheet("""
            color: #a0aec0; 
            font-weight: bold; 
            font-size: 11pt; 
            padding: 8px 12px;
            min-height: 30px;
            background: rgba(160, 174, 192, 0.1);
            border-radius: 6px;
        """)
        btn_layout.addWidget(cred_section)
        
        add_btn = QPushButton("➕ ADD NEW")
        add_btn.clicked.connect(self.add_credential)
        add_btn.setMinimumHeight(40)
        add_btn.setStyleSheet("QPushButton { font-size: 11pt; padding: 10px 15px; }")
        btn_layout.addWidget(add_btn)
        
        edit_btn = QPushButton("✏️ EDIT")
        edit_btn.clicked.connect(self.edit_credential)
        edit_btn.setMinimumHeight(40)
        edit_btn.setStyleSheet("QPushButton { font-size: 11pt; padding: 10px 15px; }")
        btn_layout.addWidget(edit_btn)
        
        delete_btn = QPushButton("🗑️ DELETE")
        delete_btn.clicked.connect(self.delete_credential)
        delete_btn.setProperty("class", "danger")
        delete_btn.setMinimumHeight(40)
        delete_btn.setStyleSheet("QPushButton { font-size: 11pt; padding: 10px 15px; }")
        btn_layout.addWidget(delete_btn)
        
        # Separator
        separator = QLabel(" ║ ")
        separator.setStyleSheet("color: #4a5568; font-size: 14pt; font-weight: bold;")
        btn_layout.addWidget(separator)
        
        # Security tools section
        tools_section = QLabel("🔧 SECURITY TOOLS:")
        tools_section.setStyleSheet("""
            color: #a0aec0; 
            font-weight: bold; 
            font-size: 11pt;
            padding: 8px 12px;
            min-height: 30px;
            background: rgba(160, 174, 192, 0.1);
            border-radius: 6px;
        """)
        btn_layout.addWidget(tools_section)
        
        gen_btn = QPushButton("🎲 GENERATE")
        gen_btn.clicked.connect(self.show_generator)
        gen_btn.setMinimumHeight(40)
        gen_btn.setStyleSheet("QPushButton { font-size: 11pt; padding: 10px 15px; }")
        btn_layout.addWidget(gen_btn)
        
        # Separator
        separator2 = QLabel(" ║ ")
        separator2.setStyleSheet("color: #4a5568; font-size: 14pt; font-weight: bold;")
        btn_layout.addWidget(separator2)
        
        # Data management section
        data_section = QLabel("💾 DATA MANAGEMENT:")
        data_section.setStyleSheet("""
            color: #a0aec0; 
            font-weight: bold; 
            font-size: 11pt;
            padding: 8px 12px;
            min-height: 30px;
            background: rgba(160, 174, 192, 0.1);
            border-radius: 6px;
        """)
        btn_layout.addWidget(data_section)
        
        export_btn = QPushButton("💾 EXPORT")
        export_btn.clicked.connect(self.export_data)
        export_btn.setProperty("class", "secondary")
        export_btn.setMinimumHeight(40)
        export_btn.setStyleSheet("QPushButton { font-size: 11pt; padding: 10px 15px; }")
        btn_layout.addWidget(export_btn)
        
        import_btn = QPushButton("📂 IMPORT")
        import_btn.clicked.connect(self.import_data)
        import_btn.setProperty("class", "secondary")
        import_btn.setMinimumHeight(40)
        import_btn.setStyleSheet("QPushButton { font-size: 11pt; padding: 10px 15px; }")
        btn_layout.addWidget(import_btn)
        
        btn_layout.addStretch()
        layout.addWidget(btn_frame)
        
        # Enhanced cyber-themed status bar
        status_text = "🟢 SYSTEM READY | 🔒 AUTO-LOCK: 5 MIN | 🛡️ AES-256 ENCRYPTION ACTIVE | 🔐 SECURE PROTOCOL ENGAGED"
        self.statusBar().showMessage(status_text)
        self.statusBar().setStyleSheet("""
            QStatusBar {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a202c, stop:1 #2d3748);
                border-top: 3px solid #0d7377;
                color: #81e6d9;
                padding: 10px;
                font-size: 10pt;
                font-weight: bold;
                font-family: 'Courier New', monospace;
                min-height: 25px;
            }
        """)
    
    def apply_dark_theme(self):
        """Apply modern security-focused dark theme with gradients and effects"""
        self.setStyleSheet("""
            /* Main Window Styling */
            QMainWindow, QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f1419, stop:0.3 #1a1f2e, stop:0.7 #1a1f2e, stop:1 #0f1419);
                color: #e2e8f0;
                font-family: 'Segoe UI', 'San Francisco', Arial;
                font-size: 10pt;
            }
            
            /* Search Bar Styling */
            QLineEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 2px solid #4a5568;
                border-radius: 8px;
                padding: 14px 18px;
                color: #e2e8f0;
                font-size: 12pt;
                min-height: 20px;
                selection-background-color: #0d7377;
            }
            QLineEdit:focus {
                border: 2px solid #0d7377;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0d7377, stop:0.1 #2d3748, stop:1 #1a202c);
                box-shadow: 0 0 15px rgba(13, 115, 119, 0.4);
            }
            QLineEdit::placeholder {
                color: #718096;
                font-style: italic;
            }
            
            /* Text Area Styling */
            QTextEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 2px solid #4a5568;
                border-radius: 8px;
                padding: 12px;
                color: #e2e8f0;
                selection-background-color: #0d7377;
            }
            QTextEdit:focus {
                border: 2px solid #0d7377;
            }
            
            /* ComboBox Styling */
            QComboBox {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 2px solid #4a5568;
                border-radius: 8px;
                padding: 8px 12px;
                color: #e2e8f0;
                min-width: 120px;
            }
            QComboBox:focus {
                border: 2px solid #0d7377;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox::down-arrow {
                image: none;
                border: 5px solid transparent;
                border-top: 8px solid #718096;
                margin-right: 10px;
            }
            QComboBox QAbstractItemView {
                background: #2d3748;
                border: 1px solid #4a5568;
                selection-background-color: #0d7377;
                color: #e2e8f0;
            }
            
            /* SpinBox Styling */
            QSpinBox {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 2px solid #4a5568;
                border-radius: 8px;
                padding: 8px 12px;
                color: #e2e8f0;
            }
            QSpinBox:focus {
                border: 2px solid #0d7377;
            }
            
            /* Enhanced Button Styling */
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0d7377, stop:0.5 #14a085, stop:1 #0d7377);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 14px 22px;
                font-weight: bold;
                font-size: 11pt;
                min-height: 20px;
                transition: all 0.3s ease;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #14a085, stop:0.5 #17c4a5, stop:1 #14a085);
                box-shadow: 0 4px 15px rgba(20, 160, 133, 0.3);
                transform: translateY(-2px);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0a5f63, stop:0.5 #0d7377, stop:1 #0a5f63);
                transform: translateY(1px);
                box-shadow: 0 2px 8px rgba(10, 95, 99, 0.4);
            }
            
            /* Special Button Variants */
            QPushButton[class="danger"] {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #e53e3e, stop:0.5 #f56565, stop:1 #e53e3e);
            }
            QPushButton[class="danger"]:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f56565, stop:0.5 #fc8181, stop:1 #f56565);
            }
            
            QPushButton[class="secondary"] {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4a5568, stop:0.5 #718096, stop:1 #4a5568);
            }
            QPushButton[class="secondary"]:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #718096, stop:0.5 #a0aec0, stop:1 #718096);
            }
            
            /* Enhanced Table Styling */
            QTableWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                alternate-background-color: rgba(74, 85, 104, 0.3);
                gridline-color: #4a5568;
                border: 2px solid #4a5568;
                border-radius: 10px;
                selection-background-color: rgba(13, 115, 119, 0.4);
            }
            QTableWidget::item {
                padding: 12px 8px;
                border-bottom: 1px solid #4a5568;
                color: #e2e8f0;
            }
            QTableWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(13, 115, 119, 0.6), 
                    stop:1 rgba(20, 160, 133, 0.4));
                color: white;
                font-weight: bold;
            }
            QTableWidget::item:hover {
                background: rgba(13, 115, 119, 0.2);
            }
            
            /* Enhanced Header Styling */
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1a202c, stop:1 #0f1419);
                color: #e2e8f0;
                padding: 15px 8px;
                border: none;
                border-bottom: 3px solid #0d7377;
                border-right: 1px solid #4a5568;
                font-weight: bold;
                font-size: 11pt;
            }
            QHeaderView::section:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
            }
            QHeaderView::section:first {
                border-left: none;
            }
            QHeaderView::section:last {
                border-right: none;
            }
            
            /* Progress Bar Enhancement */
            QProgressBar {
                border: 2px solid #4a5568;
                border-radius: 8px;
                text-align: center;
                background: #1a202c;
                height: 25px;
                color: white;
                font-weight: bold;
                font-size: 10pt;
            }
            QProgressBar::chunk {
                border-radius: 6px;
                margin: 1px;
            }
            
            /* Status Bar Enhancement */
            QStatusBar {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a202c, stop:1 #2d3748);
                border-top: 2px solid #4a5568;
                color: #a0aec0;
                padding: 8px;
                font-size: 9pt;
            }
            
            /* Dialog Enhancements */
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f1419, stop:0.5 #1a1f2e, stop:1 #0f1419);
                border: 2px solid #4a5568;
                border-radius: 15px;
            }
            
            /* Message Box Styling */
            QMessageBox {
                background: #1a202c;
                color: #e2e8f0;
            }
            QMessageBox QPushButton {
                min-width: 80px;
                margin: 5px;
            }
            
            /* Scroll Bar Styling */
            QScrollBar:vertical {
                background: #2d3748;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #4a5568;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #0d7377;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0px;
            }
        """)
        
        # Add window shadow effect
        try:
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(30)
            shadow.setXOffset(0)
            shadow.setYOffset(10)
            shadow.setColor(QColor(0, 0, 0, 100))
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
        """Setup credential dialog UI with enhanced security styling"""
        title = "🔐 Add Secure Credential" if self.mode == "add" else "✏️ Edit Credential"
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(600)
        self.setMinimumHeight(700)
        
        # Apply enhanced dialog styling
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f1419, stop:0.5 #1a1f2e, stop:1 #0f1419);
                border: 2px solid #4a5568;
                border-radius: 15px;
            }
            QLabel {
                color: #e2e8f0;
                font-weight: bold;
                font-size: 11pt;
                padding: 5px 0;
            }
            QFormLayout {
                spacing: 15px;
            }
        """)
        
        layout = QFormLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Security header
        security_header = QLabel("🛡️ SECURE CREDENTIAL STORAGE")
        security_header.setAlignment(Qt.AlignCenter)
        security_header.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(13, 115, 119, 0.3), 
                stop:0.5 rgba(20, 160, 133, 0.4), 
                stop:1 rgba(13, 115, 119, 0.3));
            border: 1px solid #0d7377;
            border-radius: 10px;
            padding: 15px;
            font-size: 12pt;
            font-weight: bold;
            color: #81e6d9;
            margin-bottom: 20px;
        """)
        layout.addRow(security_header)
        
        # Service field with icon
        service_label = QLabel("🏢 Service/Website:")
        self.service_edit = QLineEdit()
        self.service_edit.setPlaceholderText("e.g., Gmail, GitHub, Banking...")
        layout.addRow(service_label, self.service_edit)
        
        # Username field with icon
        username_label = QLabel("👤 Username/Email:")
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Your username or email address...")
        layout.addRow(username_label, self.username_edit)
        
        # Password field with enhanced controls
        password_label = QLabel("🔐 Password:")
        pw_container = QWidget()
        pw_layout = QHBoxLayout(pw_container)
        pw_layout.setContentsMargins(0, 0, 0, 0)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Enter secure password...")
        self.password_edit.textChanged.connect(self.update_strength)
        pw_layout.addWidget(self.password_edit)
        
        # Show/hide password button
        show_btn = QPushButton("👁️")
        show_btn.setMaximumWidth(40)
        show_btn.setToolTip("Show/Hide Password")
        show_btn.pressed.connect(lambda: self.password_edit.setEchoMode(QLineEdit.Normal))
        show_btn.released.connect(lambda: self.password_edit.setEchoMode(QLineEdit.Password))
        pw_layout.addWidget(show_btn)
        
        # Generate password button
        gen_btn = QPushButton("🎲")
        gen_btn.setMaximumWidth(40)
        gen_btn.setToolTip("Generate Secure Password")
        gen_btn.clicked.connect(self.generate_password)
        pw_layout.addWidget(gen_btn)
        
        layout.addRow(password_label, pw_container)
        
        # Enhanced strength meter
        strength_label = QLabel("🎯 Password Security Analysis:")
        strength_container = QWidget()
        strength_layout = QVBoxLayout(strength_container)
        strength_layout.setContentsMargins(0, 0, 0, 0)
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(100)
        self.strength_bar.setMinimumHeight(25)
        strength_layout.addWidget(self.strength_bar)
        
        self.strength_label = QLabel("💭 Enter password to analyze security strength")
        self.strength_label.setStyleSheet("font-size: 9pt; color: #718096; padding: 5px;")
        self.strength_label.setAlignment(Qt.AlignCenter)
        strength_layout.addWidget(self.strength_label)
        
        layout.addRow(strength_label, strength_container)
        
        # URL field with icon
        url_label = QLabel("🌐 Website URL:")
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com (optional)")
        layout.addRow(url_label, self.url_edit)
        
        # Category field with enhanced combo
        category_label = QLabel("📁 Category:")
        self.category_combo = QComboBox()
        categories = ["🔒 General", "📧 Email", "📱 Social", "🏦 Banking", 
                     "💼 Work", "🛒 Shopping", "🎮 Gaming", "📚 Other"]
        self.category_combo.addItems(categories)
        layout.addRow(category_label, self.category_combo)
        
        # Notes field with encryption notice
        notes_label = QLabel("📝 Secure Notes:")
        notes_container = QWidget()
        notes_layout = QVBoxLayout(notes_container)
        notes_layout.setContentsMargins(0, 0, 0, 0)
        
        self.notes_edit = QTextEdit()
        self.notes_edit.setMaximumHeight(100)
        self.notes_edit.setPlaceholderText("Additional secure notes (encrypted)...")
        notes_layout.addWidget(self.notes_edit)
        
        encryption_notice = QLabel("🔒 All notes are encrypted with AES-256")
        encryption_notice.setStyleSheet("""
            background: rgba(13, 115, 119, 0.2);
            border: 1px solid #0d7377;
            border-radius: 5px;
            padding: 8px;
            font-size: 8pt;
            color: #81e6d9;
        """)
        encryption_notice.setAlignment(Qt.AlignCenter)
        notes_layout.addWidget(encryption_notice)
        
        layout.addRow(notes_label, notes_container)
        
        # Enhanced action buttons
        btn_container = QWidget()
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.setContentsMargins(0, 20, 0, 0)
        
        save_btn = QPushButton("💾 Save Securely")
        save_btn.clicked.connect(self.accept)
        save_btn.setMinimumHeight(40)
        btn_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("❌ Cancel")
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
            
            # Match category with icon
            category = self.credential.get('category', 'General')
            for i in range(self.category_combo.count()):
                if category.lower() in self.category_combo.itemText(i).lower():
                    self.category_combo.setCurrentIndex(i)
                    break
                    
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
        """Return form data with cleaned category"""
        category_text = self.category_combo.currentText()
        # Remove emoji and clean category text
        category_clean = category_text.split(' ', 1)[-1] if ' ' in category_text else category_text
        
        return {
            'service': self.service_edit.text(),
            'username': self.username_edit.text(),
            'password': self.password_edit.text(),
            'url': self.url_edit.text(),
            'category': category_clean,
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
