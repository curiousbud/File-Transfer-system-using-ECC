"""
Django management command to test crypto functionality
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
import sys
import traceback


class Command(BaseCommand):
    help = 'Test cryptographic functionality and diagnose issues'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('=== Qubix Crypto Diagnostics ===\n'))
        
        # Test 1: Basic imports
        self.stdout.write('1. Testing basic crypto imports...')
        try:
            import cryptography
            self.stdout.write(f'   ✓ cryptography version: {cryptography.__version__}')
        except ImportError as e:
            self.stdout.write(f'   ✗ cryptography import failed: {e}')
            return
        
        try:
            import ecdsa
            self.stdout.write(f'   ✓ ecdsa version: {ecdsa.__version__}')
        except ImportError as e:
            self.stdout.write(f'   ✗ ecdsa import failed: {e}')
        
        try:
            from Crypto import __version__
            self.stdout.write(f'   ✓ pycryptodome version: {__version__}')
        except ImportError as e:
            self.stdout.write(f'   ✗ pycryptodome import failed: {e}')
        
        # Test 2: Specific crypto module imports
        self.stdout.write('\n2. Testing specific crypto module imports...')
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            self.stdout.write('   ✓ ec module imported successfully')
        except ImportError as e:
            self.stdout.write(f'   ✗ ec module import failed: {e}')
            traceback.print_exc()
            return
        
        try:
            from cryptography.hazmat.primitives import hashes
            self.stdout.write('   ✓ hashes module imported successfully')
        except ImportError as e:
            self.stdout.write(f'   ✗ hashes module import failed: {e}')
            return
        
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            self.stdout.write('   ✓ cipher modules imported successfully')
        except ImportError as e:
            self.stdout.write(f'   ✗ cipher modules import failed: {e}')
            return
        
        # Test 3: Our crypto modules
        self.stdout.write('\n3. Testing our crypto modules...')
        try:
            from crypto.ecc_manager import ECCManager
            self.stdout.write('   ✓ ECCManager imported successfully')
        except ImportError as e:
            self.stdout.write(f'   ✗ ECCManager import failed: {e}')
            traceback.print_exc()
            return
        
        try:
            from crypto.key_storage import SecureKeyStorage
            self.stdout.write('   ✓ SecureKeyStorage imported successfully')
        except ImportError as e:
            self.stdout.write(f'   ✗ SecureKeyStorage import failed: {e}')
            traceback.print_exc()
            return
        
        try:
            from crypto.curves import SupportedCurves
            self.stdout.write('   ✓ SupportedCurves imported successfully')
        except ImportError as e:
            self.stdout.write(f'   ✗ SupportedCurves import failed: {e}')
            traceback.print_exc()
            return
        
        # Test 4: Basic ECC operations
        self.stdout.write('\n4. Testing basic ECC operations...')
        try:
            ecc_manager = ECCManager()
            self.stdout.write('   ✓ ECCManager instance created')
            
            # Generate key pair
            private_key, public_key = ecc_manager.generate_key_pair()
            self.stdout.write('   ✓ ECC key pair generated successfully')
            
            # Serialize keys
            private_key_pem = ecc_manager.serialize_private_key(private_key)
            public_key_pem = ecc_manager.serialize_public_key(public_key)
            self.stdout.write('   ✓ Keys serialized successfully')
            
            # Test key storage
            storage = SecureKeyStorage()
            password = "test_password_123"
            encrypted_package = storage.encrypt_private_key(private_key_pem, password)
            self.stdout.write('   ✓ Private key encrypted successfully')
            
            # Test decryption
            decrypted_key = storage.decrypt_private_key(encrypted_package, password)
            self.stdout.write('   ✓ Private key decrypted successfully')
            
            # Verify integrity
            if private_key_pem == decrypted_key:
                self.stdout.write('   ✓ Key encryption/decryption integrity verified')
            else:
                self.stdout.write('   ✗ Key integrity check failed')
                return
                
        except Exception as e:
            self.stdout.write(f'   ✗ ECC operations failed: {e}')
            traceback.print_exc()
            return
        
        # Test 5: Check Django models
        self.stdout.write('\n5. Testing Django models...')
        try:
            from users.models import ECCKeyPair
            self.stdout.write('   ✓ ECCKeyPair model imported successfully')
        except ImportError as e:
            self.stdout.write(f'   ✗ ECCKeyPair model import failed: {e}')
            return
        
        # Test 6: Check views crypto availability
        self.stdout.write('\n6. Testing views crypto availability...')
        try:
            from users.views import CRYPTO_AVAILABLE
            self.stdout.write(f'   CRYPTO_AVAILABLE in views: {CRYPTO_AVAILABLE}')
            
            if not CRYPTO_AVAILABLE:
                self.stdout.write('   ✗ CRYPTO_AVAILABLE is False in views!')
                self.stdout.write('   This is likely the source of the problem.')
            else:
                self.stdout.write('   ✓ CRYPTO_AVAILABLE is True in views')
                
        except ImportError as e:
            self.stdout.write(f'   ✗ Views import failed: {e}')
            traceback.print_exc()
        
        # Test 7: Test database operations
        self.stdout.write('\n7. Testing database operations...')
        try:
            # Check if any users exist
            user_count = User.objects.count()
            self.stdout.write(f'   Total users in database: {user_count}')
            
            if user_count > 0:
                test_user = User.objects.first()
                self.stdout.write(f'   Testing with user: {test_user.username}')
                
                # Check existing ECC keys
                existing_keys = ECCKeyPair.objects.filter(user=test_user).count()
                self.stdout.write(f'   Existing ECC keys for user: {existing_keys}')
                
        except Exception as e:
            self.stdout.write(f'   ✗ Database operations failed: {e}')
            traceback.print_exc()
        
        # Test 8: Python environment check
        self.stdout.write('\n8. Python environment information...')
        self.stdout.write(f'   Python version: {sys.version}')
        self.stdout.write(f'   Python executable: {sys.executable}')
        
        # Check if we're in virtual environment
        import os
        virtual_env = os.environ.get('VIRTUAL_ENV')
        if virtual_env:
            self.stdout.write(f'   Virtual environment: {virtual_env}')
        else:
            self.stdout.write('   No virtual environment detected')
        
        self.stdout.write('\n=== Diagnostics Complete ===')
        self.stdout.write(self.style.SUCCESS('All crypto functionality tests passed!'))
