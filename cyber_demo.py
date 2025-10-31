#!/usr/bin/env python3
"""
SecurePass Cybersecurity Demo Script
Showcases the advanced cybersecurity-themed interface
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    """Launch SecurePass with cybersecurity interface"""
    try:
        print("⚡" * 60)
        print("⚡ SECUREPASS - CYBER DEFENSE MATRIX ⚡")
        print("⚡" * 60)
        print("🔺 INITIALIZING CYBER SECURITY INTERFACE...")
        print("⚡ SYSTEM STATUS: ONLINE")
        print("🔐 ENCRYPTION: AES-256 ACTIVE")
        print("⛨ THREAT LEVEL: SECURE")
        print("=" * 60)
        print("🎯 CYBER FEATURES ENABLED:")
        print("   ⚡ Neon cyberpunk login interface")
        print("   🔺 Matrix-style terminal aesthetics") 
        print("   ⛨ Real-time security monitoring")
        print("   🔐 Advanced encryption visualizations")
        print("   🎮 Cybersecurity-focused color scheme")
        print("   ⚡ Animated neon glow effects")
        print("   🔺 Futuristic control panels")
        print("=" * 60)
        print("🚀 LAUNCHING CYBER DEFENSE SYSTEM...")
        print("⚡" * 60)
        
        # Import and run the main application
        from main import main as run_app
        run_app()
        
    except ImportError as e:
        print(f"❌ SYSTEM ERROR: Missing cyber modules - {e}")
        print("📋 DEPLOY REQUIRED CYBER PACKAGES:")
        print("   >>> pip install -r requirements.txt")
        print("\n🔧 REQUIRED CYBER DEPENDENCIES:")
        print("   ⚡ PyQt5 >= 5.15.0 (Cyber GUI Framework)")
        print("   🔐 cryptography >= 3.4.8 (Advanced Encryption)")
        print("   📋 pyperclip >= 1.8.2 (Secure Clipboard)")
        
    except Exception as e:
        print(f"❌ CYBER SYSTEM FAILURE: {e}")
        print("🔧 CHECK CYBER DEFENSE PROTOCOLS AND DEPENDENCIES")

if __name__ == '__main__':
    main()
