#!/usr/bin/env python3
"""
SecurePass Cybersecurity Demo
Showcasing enhanced security interface with cyber animations
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def print_cyber_banner():
    """Print cybersecurity-themed banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║  🛡️  SecurePass - CYBERSECURITY ENHANCED PASSWORD MANAGER  🛡️  ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  ┌─[ SECURITY FEATURES ]─────────────────────────────────┐   ║
║  │  🔒 Military-Grade AES-256 Encryption                 │   ║
║  │  🔐 Matrix-Style Cyber Animations                     │   ║
║  │  🎯 Real-Time Security Monitoring                     │   ║
║  │  ⚡ Scanning Line Visual Effects                      │   ║
║  │  🌐 Cyber Grid Background Patterns                    │   ║
║  │  🛡️ Enhanced Security Status Indicators               │   ║
║  └────────────────────────────────────────────────────────┘   ║
║                                                              ║
║  ┌─[ VISUAL ENHANCEMENTS ]───────────────────────────────┐   ║
║  │  🎨 Cyberpunk-Themed Dark Interface                   │   ║
║  │  ✨ Smooth Hover & Transition Effects                 │   ║
║  │  📊 Animated Security Protocols                       │   ║
║  │  🔧 Professional Font Sizing & Spacing                │   ║
║  │  🖥️ High-Resolution Cyber Graphics                    │   ║
║  │  📱 Responsive Security Dashboard                      │   ║
║  └────────────────────────────────────────────────────────┘   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)

def main():
    """Launch SecurePass with cybersecurity enhancements"""
    try:
        print_cyber_banner()
        print("🔐 Initializing cybersecurity protocols...")
        print("🛡️ Loading enhanced security interface...")
        print("⚡ Starting cyber animations...")
        print("🎯 Activating security monitoring...")
        print("🔒 Encrypting all communications...")
        print("=" * 65)
        
        # Import and run the main application
        from main import main as run_app
        run_app()
        
    except ImportError as e:
        print(f"❌ SECURITY ERROR: Missing dependencies - {e}")
        print("\n🔧 REQUIRED SECURITY MODULES:")
        print("   📦 PyQt5 >= 5.15.0 (GUI Framework)")
        print("   🔐 cryptography >= 3.4.8 (Encryption)")
        print("   📋 pyperclip >= 1.8.2 (Secure Clipboard)")
        print("\n💻 INSTALLATION COMMAND:")
        print("   pip install -r requirements.txt")
        
    except Exception as e:
        print(f"❌ SYSTEM ERROR: {e}")
        print("🔧 Check your security configuration and try again")

if __name__ == '__main__':
    main()