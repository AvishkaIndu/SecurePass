# � SecurePass - Simple & User-Friendly Password Manager

A clean, intuitive password manager with strong encryption and a simple interface that anyone can use.

## � Simple & Clean Interface

### ✨ User-Friendly Design
- **Clean Login Screen**: Simple password entry with clear instructions
- **Intuitive Main Window**: Easy-to-understand layout with labeled buttons
- **Straightforward Dialogs**: Clear forms for adding and editing passwords
- **No Complexity**: Just the features you need, nothing overwhelming

### 🔧 Easy-to-Use Features
- **Simple Password List**: Clean table showing your saved passwords
- **One-Click Actions**: View, copy, edit, or delete with single clicks
- **Built-in Generator**: Create strong passwords with customizable options
- **Quick Search**: Find passwords instantly with the search box

## 🚀 Quick Start (Easy Installation)

### Minimal Requirements
```bash
# Install Python 3.6+ (if not already installed)
# Then install the only required dependency:
pip install cryptography
```

### Run the Application
```bash
# Navigate to the project directory
cd SecurePass

# Run the simple version
python demo.py
```

That's it! No complex setup or multiple dependencies.

## 🔐 Security Features (Simple but Strong)

### 🛡️ Strong Protection
- **AES-256 Encryption**: Military-grade security for all your passwords
- **Master Password**: One password protects everything
- **Local Storage**: Your data never leaves your computer
- **No Online Dependencies**: Works completely offline

### 🔒 Safe Usage
- **Auto-Lock**: Protects your vault when you step away
- **Secure Clipboard**: Passwords are automatically cleared from clipboard
- **No Password Storage**: Your master password is never saved
- **Encrypted Everything**: Notes, URLs, and passwords are all encrypted

## 📱 Simple Interface Guide

### � Main Window Features
- **Search Box**: Type to find passwords quickly
- **Password Table**: See all your saved accounts at a glance
- **Action Buttons**: Clear, labeled buttons for each function
- **Status Bar**: Shows what's happening and confirms actions

### 🔧 Easy Functions
- **➕ Add New**: Create a new password entry
- **✏️ Edit**: Modify existing password information
- **🗑️ Delete**: Remove passwords you no longer need
- **👁️ View Password**: See the actual password securely
- **📋 Copy Password**: Copy to clipboard for easy pasting
- **🎲 Generate Password**: Create strong, random passwords

## 💡 How to Use

### First Time Setup
1. **Launch**: Run the application
2. **Create Master Password**: Choose a strong password you'll remember
3. **Confirm**: Re-enter your password to confirm
4. **Done**: Your secure vault is created!

### Daily Usage
1. **Unlock**: Enter your master password
2. **Add Passwords**: Click "Add New" to save account details
3. **Find Passwords**: Use search or scroll through the list
4. **Copy & Use**: Click "Copy Password" to use in other apps
5. **Stay Secure**: The app auto-locks for your protection

## � Technical Details (Simple)

### 📁 What You Get
```
SecurePass/
├── src/
│   ├── main_simple.py   # Simple tkinter interface
│   ├── crypto_lib.py    # Encryption functions
│   ├── db.py           # Database management
│   └── utils.py        # Password generation & checking
├── demo.py             # Easy launcher script
├── requirements.txt    # Minimal dependencies
└── README.md          # This guide
```

### 🔐 How Security Works
- **Your master password** creates an encryption key
- **All data is encrypted** before being saved to your computer
- **The master password** is never stored anywhere
- **Even if someone gets your files**, they can't read them without your master password

## 🎯 Why This Version?

### ✅ Advantages
- **No Complex Dependencies**: Uses built-in Python tkinter
- **Easy Installation**: Just install cryptography library
- **Simple Interface**: No confusing menus or options
- **Fast Setup**: Running in minutes, not hours
- **Reliable**: Uses standard, well-tested components

### � Still Secure
- **Same Encryption**: Uses the same AES-256 as professional tools
- **Same Security**: Your data is just as protected
- **Local Only**: No internet required, no cloud dependencies
- **Private**: Your passwords stay on your computer

## 🚀 Getting Started Examples

### Installing Dependencies
```bash
# On Windows
pip install cryptography

# On Mac/Linux
pip3 install cryptography
```

### Running the App
```bash
# Method 1: Use the demo launcher
python demo.py

# Method 2: Run directly
python src/main_simple.py
```

### Creating Your First Password
1. Click "Add New"
2. Enter website name (e.g., "Gmail")
3. Enter your username
4. Enter your password (or click generate)
5. Click "Save"
6. Done!

## 🛡️ Security Tips

- **Choose a strong master password** you can remember
- **Don't share your master password** with anyone
- **Keep the app updated** for security improvements
- **Backup your vault file** (it's encrypted, so it's safe to store)
- **Use the password generator** for new accounts

## 🤝 Perfect For

- **Home Users**: Simple password management for personal use
- **Small Teams**: Easy sharing of the application
- **Students**: Learning about password security
- **Anyone**: Who wants security without complexity

---

**SecurePass Simple** - Strong security, simple interface, easy to use!
