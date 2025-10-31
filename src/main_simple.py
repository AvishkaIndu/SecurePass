"""
SecurePass Password Manager - Simple & User-Friendly Interface
Built with tkinter for maximum compatibility and simplicity
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sys
import os
from crypto_lib import CryptoManager
from db import DatabaseManager
from utils import PasswordStrengthChecker, PasswordGenerator


class SimpleLoginWindow:
    """Simple and clean login window"""
    
    def __init__(self):
        self.crypto = CryptoManager()
        self.db = DatabaseManager()
        self.setup_mode = self.db.get_config('salt') is None
        self.root = tk.Tk()
        self.setup_ui()
        
    def setup_ui(self):
        """Create a simple, clean login interface"""
        self.root.title("SecurePass - Login")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        # Center the window
        self.root.eval('tk::PlaceWindow . center')
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="30")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 SecurePass", 
                               font=("Arial", 18, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Subtitle
        subtitle_text = "Create Master Password" if self.setup_mode else "Enter Master Password"
        subtitle_label = ttk.Label(main_frame, text=subtitle_text, 
                                  font=("Arial", 10))
        subtitle_label.grid(row=1, column=0, columnspan=2, pady=(0, 20))
        
        # Password entry
        ttk.Label(main_frame, text="Master Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                       show="*", width=25)
        self.password_entry.grid(row=3, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))
        self.password_entry.bind('<Return>', lambda e: self.handle_login())
        
        if self.setup_mode:
            # Confirm password for setup
            ttk.Label(main_frame, text="Confirm Password:").grid(row=4, column=0, sticky=tk.W, pady=5)
            self.confirm_var = tk.StringVar()
            self.confirm_entry = ttk.Entry(main_frame, textvariable=self.confirm_var, 
                                          show="*", width=25)
            self.confirm_entry.grid(row=5, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))
            self.confirm_entry.bind('<Return>', lambda e: self.handle_login())
            
            # Warning message
            warning_label = ttk.Label(main_frame, 
                                     text="⚠️ Remember this password!\nIt cannot be recovered if lost.",
                                     font=("Arial", 9), foreground="red")
            warning_label.grid(row=6, column=0, columnspan=2, pady=10)
        
        # Login button
        button_text = "Create Vault" if self.setup_mode else "Unlock Vault"
        login_btn = ttk.Button(main_frame, text=button_text, command=self.handle_login)
        login_btn.grid(row=7, column=0, columnspan=2, pady=20, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Focus on password entry
        self.password_entry.focus()
    
    def handle_login(self):
        """Handle login or setup"""
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
            
        if self.setup_mode:
            # Setup mode
            confirm = self.confirm_var.get()
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return
                
            if len(password) < 6:
                result = messagebox.askyesno("Weak Password", 
                                           "Your password is short. Continue anyway?")
                if not result:
                    return
            
            try:
                # Generate salt and derive key
                self.crypto.derive_key(password)
                
                # Store salt and iterations
                self.db.save_config('salt', self.crypto.get_salt_b64())
                self.db.save_config('iterations', str(CryptoManager.ITERATIONS))
                
                messagebox.showinfo("Success", "Vault created successfully!")
                self.launch_main_window()
            except Exception as e:
                messagebox.showerror("Error", f"Setup failed: {str(e)}")
        else:
            # Login mode
            try:
                # Load salt
                salt_b64 = self.db.get_config('salt')
                self.crypto.set_salt_from_b64(salt_b64)
                
                # Derive key from password
                self.crypto.derive_key(password, self.crypto.salt)
                
                # Verify by attempting to decrypt a credential (if any exist)
                credentials = self.db.get_all_credentials()
                if credentials:
                    try:
                        self.crypto.decrypt(credentials[0]['password_encrypted'])
                    except:
                        messagebox.showerror("Error", "Invalid master password")
                        return
                
                self.launch_main_window()
            except Exception as e:
                messagebox.showerror("Error", f"Login failed: {str(e)}")
    
    def launch_main_window(self):
        """Launch the main application window"""
        self.root.destroy()
        app = SimpleMainWindow(self.crypto, self.db)
        app.run()
    
    def run(self):
        """Start the login window"""
        self.root.mainloop()


class SimpleMainWindow:
    """Simple and user-friendly main window"""
    
    def __init__(self, crypto, db):
        self.crypto = crypto
        self.db = db
        self.root = tk.Tk()
        self.setup_ui()
        self.load_credentials()
        
    def setup_ui(self):
        """Create a simple, clean main interface"""
        self.root.title("SecurePass - Password Manager")
        self.root.geometry("800x600")
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.grid(row=0, column=1, padx=5)
        self.search_var.trace('w', lambda *args: self.search_credentials())
        
        # Lock button
        lock_btn = ttk.Button(search_frame, text="🔒 Lock", command=self.lock_vault)
        lock_btn.grid(row=0, column=2, padx=10)
        
        # Credentials list frame
        list_frame = ttk.Frame(main_frame)
        list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Treeview for credentials
        columns = ('Service', 'Username', 'Category')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        self.tree.heading('Service', text='Service/Website')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Category', text='Category')
        
        # Configure column widths
        self.tree.column('Service', width=200)
        self.tree.column('Username', width=200)
        self.tree.column('Category', width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        # Create buttons
        ttk.Button(button_frame, text="➕ Add New", command=self.add_credential).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="✏️ Edit", command=self.edit_credential).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="🗑️ Delete", command=self.delete_credential).grid(row=0, column=2, padx=5)
        ttk.Button(button_frame, text="👁️ View Password", command=self.view_password).grid(row=0, column=3, padx=5)
        ttk.Button(button_frame, text="📋 Copy Password", command=self.copy_password).grid(row=0, column=4, padx=5)
        ttk.Button(button_frame, text="🎲 Generate Password", command=self.generate_password).grid(row=0, column=5, padx=5)
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        search_frame.columnconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - SecurePass Password Manager")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def load_credentials(self, search_term=""):
        """Load credentials into the tree view"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Load credentials from database
        credentials = self.db.get_all_credentials(search_term)
        
        for cred in credentials:
            self.tree.insert('', tk.END, values=(
                cred['service'],
                cred['username'],
                cred.get('category', 'General')
            ), tags=(str(cred['id']),))
    
    def search_credentials(self):
        """Filter credentials based on search term"""
        search_term = self.search_var.get()
        self.load_credentials(search_term)
    
    def get_selected_credential(self):
        """Get the currently selected credential"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a credential first")
            return None
            
        item = self.tree.item(selection[0])
        service = item['values'][0]
        
        # Get full credential data
        credentials = self.db.get_all_credentials()
        for cred in credentials:
            if cred['service'] == service:
                return cred
        return None
    
    def add_credential(self):
        """Add a new credential"""
        dialog = SimpleCredentialDialog(self.root, self.crypto, mode="add")
        if dialog.result:
            data = dialog.result
            self.db.add_credential(
                service=data['service'],
                username=data['username'],
                password_encrypted=self.crypto.encrypt(data['password']),
                url=data.get('url', ''),
                notes_encrypted=self.crypto.encrypt(data.get('notes', '')),
                category=data.get('category', 'General')
            )
            self.load_credentials()
            self.status_var.set("✅ Credential added successfully")
    
    def edit_credential(self):
        """Edit the selected credential"""
        cred = self.get_selected_credential()
        if not cred:
            return
            
        dialog = SimpleCredentialDialog(self.root, self.crypto, mode="edit", credential=cred)
        if dialog.result:
            data = dialog.result
            self.db.update_credential(
                cred_id=cred['id'],
                service=data['service'],
                username=data['username'],
                password_encrypted=self.crypto.encrypt(data['password']),
                url=data.get('url', ''),
                notes_encrypted=self.crypto.encrypt(data.get('notes', '')),
                category=data.get('category', 'General')
            )
            self.load_credentials()
            self.status_var.set("✅ Credential updated successfully")
    
    def delete_credential(self):
        """Delete the selected credential"""
        cred = self.get_selected_credential()
        if not cred:
            return
            
        result = messagebox.askyesno("Confirm Delete", 
                                    f"Delete credential for '{cred['service']}'?")
        if result:
            self.db.delete_credential(cred['id'])
            self.load_credentials()
            self.status_var.set("✅ Credential deleted")
    
    def view_password(self):
        """View the password for selected credential"""
        cred = self.get_selected_credential()
        if not cred:
            return
            
        try:
            password = self.crypto.decrypt(cred['password_encrypted'])
            messagebox.showinfo("Password", f"Password for {cred['service']}:\n\n{password}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")
    
    def copy_password(self):
        """Copy password to clipboard"""
        cred = self.get_selected_credential()
        if not cred:
            return
            
        try:
            password = self.crypto.decrypt(cred['password_encrypted'])
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.status_var.set("📋 Password copied to clipboard")
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")
    
    def generate_password(self):
        """Open password generator"""
        dialog = SimplePasswordGenerator(self.root)
        if dialog.result:
            messagebox.showinfo("Generated Password", f"Password: {dialog.result}")
    
    def lock_vault(self):
        """Lock the vault and return to login"""
        self.root.destroy()
        login = SimpleLoginWindow()
        login.run()
    
    def run(self):
        """Start the main window"""
        self.root.mainloop()


class SimpleCredentialDialog:
    """Simple dialog for adding/editing credentials"""
    
    def __init__(self, parent, crypto, mode="add", credential=None):
        self.parent = parent
        self.crypto = crypto
        self.mode = mode
        self.credential = credential
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Create simple credential dialog"""
        title = "Add Credential" if self.mode == "add" else "Edit Credential"
        self.dialog.title(title)
        self.dialog.geometry("400x350")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (
            self.parent.winfo_rootx() + 50,
            self.parent.winfo_rooty() + 50
        ))
        
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Form fields
        row = 0
        
        ttk.Label(main_frame, text="Service/Website:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.service_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.service_var, width=30).grid(row=row, column=1, pady=5, sticky=(tk.W, tk.E))
        row += 1
        
        ttk.Label(main_frame, text="Username:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.username_var, width=30).grid(row=row, column=1, pady=5, sticky=(tk.W, tk.E))
        row += 1
        
        ttk.Label(main_frame, text="Password:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        password_frame = ttk.Frame(main_frame)
        password_frame.grid(row=row, column=1, pady=5, sticky=(tk.W, tk.E))
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=25)
        self.password_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))
        ttk.Button(password_frame, text="👁️", width=3, command=self.toggle_password).grid(row=0, column=1, padx=(5, 0))
        password_frame.columnconfigure(0, weight=1)
        row += 1
        
        ttk.Label(main_frame, text="Website URL:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.url_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.url_var, width=30).grid(row=row, column=1, pady=5, sticky=(tk.W, tk.E))
        row += 1
        
        ttk.Label(main_frame, text="Category:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.category_var = tk.StringVar()
        category_combo = ttk.Combobox(main_frame, textvariable=self.category_var, width=27)
        category_combo['values'] = ('General', 'Email', 'Social', 'Banking', 'Work', 'Shopping', 'Other')
        category_combo.grid(row=row, column=1, pady=5, sticky=(tk.W, tk.E))
        category_combo.set('General')
        row += 1
        
        ttk.Label(main_frame, text="Notes:").grid(row=row, column=0, sticky=tk.NW, pady=5)
        self.notes_text = tk.Text(main_frame, width=30, height=4)
        self.notes_text.grid(row=row, column=1, pady=5, sticky=(tk.W, tk.E))
        row += 1
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Save", command=self.save).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).grid(row=0, column=1, padx=5)
        
        # Load existing data if editing
        if self.mode == "edit" and self.credential:
            self.service_var.set(self.credential['service'])
            self.username_var.set(self.credential['username'])
            try:
                pwd = self.crypto.decrypt(self.credential['password_encrypted'])
                self.password_var.set(pwd)
            except:
                pass
            self.url_var.set(self.credential.get('url', ''))
            self.category_var.set(self.credential.get('category', 'General'))
            try:
                notes = self.crypto.decrypt(self.credential.get('notes_encrypted', ''))
                self.notes_text.insert('1.0', notes)
            except:
                pass
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(0, weight=1)
        
        # Focus on service entry
        self.service_var.trace('w', lambda *args: None)  # Dummy trace to focus
        self.dialog.after(100, lambda: self.dialog.focus_set())
    
    def toggle_password(self):
        """Toggle password visibility"""
        if self.password_entry.cget('show') == '*':
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='*')
    
    def save(self):
        """Save the credential data"""
        if not self.service_var.get() or not self.password_var.get():
            messagebox.showerror("Error", "Service and Password are required")
            return
            
        self.result = {
            'service': self.service_var.get(),
            'username': self.username_var.get(),
            'password': self.password_var.get(),
            'url': self.url_var.get(),
            'category': self.category_var.get(),
            'notes': self.notes_text.get('1.0', tk.END).strip()
        }
        self.dialog.destroy()
    
    def cancel(self):
        """Cancel the dialog"""
        self.dialog.destroy()


class SimplePasswordGenerator:
    """Simple password generator dialog"""
    
    def __init__(self, parent):
        self.parent = parent
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Create simple password generator"""
        self.dialog.title("Password Generator")
        self.dialog.geometry("350x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (
            self.parent.winfo_rootx() + 50,
            self.parent.winfo_rooty() + 50
        ))
        
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Generated password display
        ttk.Label(main_frame, text="Generated Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=self.password_var, width=40, state='readonly')
        password_entry.grid(row=1, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))
        
        # Options
        ttk.Label(main_frame, text="Length:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.length_var = tk.IntVar(value=12)
        length_spin = ttk.Spinbox(main_frame, from_=6, to=50, textvariable=self.length_var, width=10)
        length_spin.grid(row=2, column=1, pady=5, sticky=tk.W)
        
        # Checkboxes
        self.uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Include uppercase letters (A-Z)", 
                       variable=self.uppercase_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Include lowercase letters (a-z)", 
                       variable=self.lowercase_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.numbers_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Include numbers (0-9)", 
                       variable=self.numbers_var).grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Include symbols (!@#$%^&*)", 
                       variable=self.symbols_var).grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Generate", command=self.generate).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Use This Password", command=self.use_password).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).grid(row=0, column=2, padx=5)
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(0, weight=1)
        
        # Generate initial password
        self.generate()
    
    def generate(self):
        """Generate a new password"""
        password = PasswordGenerator.generate(
            length=self.length_var.get(),
            use_upper=self.uppercase_var.get(),
            use_lower=self.lowercase_var.get(),
            use_digits=self.numbers_var.get(),
            use_symbols=self.symbols_var.get()
        )
        self.password_var.set(password)
    
    def use_password(self):
        """Use the generated password"""
        self.result = self.password_var.get()
        self.dialog.destroy()
    
    def cancel(self):
        """Cancel the dialog"""
        self.dialog.destroy()


def main():
    """Application entry point"""
    try:
        # Show login window
        login = SimpleLoginWindow()
        login.run()
    except Exception as e:
        print(f"Error starting application: {e}")
        input("Press Enter to continue...")


if __name__ == '__main__':
    main()