#!/usr/bin/env python3
"""
SecurePass Demo Script
Demonstrates the enhanced security-focused interface
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    """Launch SecurePass with enhanced interface"""
    try:
        print("🛡️ SecurePass - Professional Password Manager")
        print("=" * 50)
        print("🔐 Launching enhanced security interface...")
        print("✨ Features include:")
        print("   • Animated login with security indicators")
        print("   • Professional dark theme with gradients")
        print("   • Real-time password strength analysis")
        print("   • Enhanced security visual elements")
        print("   • Smooth hover effects and transitions")
        print("   • Organized security-focused layout")
        print("=" * 50)
        
        # Import and run the main application
        from main import main as run_app
        run_app()
        
    except ImportError as e:
        print(f"❌ Error: Missing dependencies - {e}")
        print("📋 Please install requirements:")
        print("   pip install -r requirements.txt")
        print("\n📦 Required packages:")
        print("   • PyQt5 >= 5.15.0")
        print("   • cryptography >= 3.4.8") 
        print("   • pyperclip >= 1.8.2")
        
    except Exception as e:
        print(f"❌ Application error: {e}")
        print("🔧 Please check your Python installation and dependencies")

if __name__ == '__main__':
    main()