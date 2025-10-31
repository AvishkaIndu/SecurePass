#!/usr/bin/env python3
"""
SecurePass Demo Script - Simple Version
Demonstrates the user-friendly interface built with tkinter
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    """Launch SecurePass with simple interface"""
    try:
        print("� SecurePass - Simple & User-Friendly Password Manager")
        print("=" * 55)
        print("🎯 Launching clean, simple interface...")
        print("✨ Features include:")
        print("   • Clean and intuitive login screen")
        print("   • Easy-to-use main window with clear buttons")
        print("   • Simple dialogs for adding/editing passwords")
        print("   • Built-in password generator")
        print("   • No complex dependencies - uses built-in tkinter")
        print("   • Clear labels and user-friendly design")
        print("=" * 55)
        
        # Import and run the simple application
        from main_simple import main as run_simple_app
        run_simple_app()
        
    except ImportError as e:
        print(f"❌ Error: Missing dependencies - {e}")
        print("📋 Please install requirements:")
        print("   pip install cryptography")
        print("\n📦 This simple version only needs:")
        print("   • Python 3.6+ (with tkinter)")
        print("   • cryptography library")
        print("   • All other components are built-in!")
        
    except Exception as e:
        print(f"❌ Application error: {e}")
        print("🔧 Please check your Python installation")

if __name__ == '__main__':
    main()