#!/usr/bin/env python3
"""
SecurePass Cyber Security Demo Script
Demonstrates the enhanced cybersecurity-focused interface with animations
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    """Launch SecurePass with enhanced cyber security interface"""
    try:
        print("🛡️  SECUREPASS - CLASSIFIED PASSWORD MANAGEMENT SYSTEM")
        print("=" * 60)
        print("🔐 [SYSTEM] Initializing cyber security interface...")
        print("🟢 [STATUS] Loading enhanced security features...")
        print()
        print("✨ CYBER SECURITY FEATURES:")
        print("   🚫 ACCESS DENIED animations for wrong passwords")
        print("   ✅ ACCESS GRANTED animations for successful login")
        print("   🔒 Terminal-style security status indicators")
        print("   ⏰ Real-time system monitoring")
        print("   🛡️ Enhanced encryption visual feedback")
        print("   📊 Cyber-style status displays")
        print("   🎯 Improved font rendering and layout")
        print()
        print("💡 TRY THIS:")
        print("   • Enter wrong password to see ACCESS DENIED animation")
        print("   • Enter correct password to see ACCESS GRANTED animation")
        print("   • Notice the cyber-style terminal elements")
        print("   • Check the real-time system status indicators")
        print("=" * 60)
        print("🚀 [LAUNCHING] Cyber Security Interface...")
        print()
        
        # Import and run the main application
        from main import main as run_app
        run_app()
        
    except ImportError as e:
        print(f"❌ [ERROR] Missing dependencies - {e}")
        print("📋 [SOLUTION] Install requirements:")
        print("   pip install -r requirements.txt")
        print()
        print("📦 [REQUIRED] Packages:")
        print("   • PyQt5 >= 5.15.0 (GUI Framework)")
        print("   • cryptography >= 3.4.8 (Encryption)") 
        print("   • pyperclip >= 1.8.2 (Clipboard Security)")
        
    except Exception as e:
        print(f"❌ [SYSTEM ERROR] {e}")
        print("🔧 [DIAGNOSTIC] Check Python installation and dependencies")

if __name__ == '__main__':
    main()