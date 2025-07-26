"""
Supported Elliptic Curves for Qubix File Transfer System

This module defines the elliptic curves supported by the system,
their security levels, and performance characteristics.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from enum import Enum


class SupportedCurves(Enum):
    """
    Enumeration of supported elliptic curves with their characteristics
    """
    
    # NIST P-256 (secp256r1) - Most widely supported, government approved
    P256 = {
        'name': 'P-256',
        'curve_class': ec.SECP256R1,
        'key_size': 256,
        'security_level': 128,  # bits of security
        'performance': 'balanced',
        'description': 'NIST P-256 curve, widely supported and government approved',
        'recommended': True
    }
    
    # NIST P-384 (secp384r1) - Higher security level
    P384 = {
        'name': 'P-384',
        'curve_class': ec.SECP384R1,
        'key_size': 384,
        'security_level': 192,  # bits of security
        'performance': 'slower',
        'description': 'NIST P-384 curve, higher security for sensitive data',
        'recommended': True
    }
    
    # secp256k1 - Bitcoin curve (for educational purposes)
    SECP256K1 = {
        'name': 'secp256k1',
        'curve_class': ec.SECP256K1,
        'key_size': 256,
        'security_level': 128,
        'performance': 'fast',
        'description': 'Bitcoin curve, fast operations but less standardized',
        'recommended': False
    }

    @classmethod
    def get_default_curve(cls):
        """Get the default recommended curve"""
        return cls.P256
    
    @classmethod
    def get_high_security_curve(cls):
        """Get the highest security curve"""
        return cls.P384
    
    @classmethod
    def get_all_curves(cls):
        """Get all available curves"""
        return [curve for curve in cls]
    
    @classmethod
    def get_recommended_curves(cls):
        """Get only recommended curves"""
        return [curve for curve in cls if curve.value['recommended']]
    
    def get_curve_instance(self):
        """Get the cryptography curve instance"""
        return self.value['curve_class']()
    
    def get_info(self):
        """Get curve information"""
        return self.value.copy()


class CurveValidator:
    """
    Validates curve selection and provides security recommendations
    """
    
    @staticmethod
    def validate_curve_for_security_level(curve: SupportedCurves, min_security_bits: int = 128):
        """
        Validate if curve meets minimum security requirements
        
        Args:
            curve: The curve to validate
            min_security_bits: Minimum security level in bits
            
        Returns:
            bool: True if curve meets security requirements
        """
        return curve.value['security_level'] >= min_security_bits
    
    @staticmethod
    def recommend_curve_for_use_case(use_case: str = 'general'):
        """
        Recommend curve based on use case
        
        Args:
            use_case: 'general', 'high_security', 'performance'
            
        Returns:
            SupportedCurves: Recommended curve
        """
        if use_case == 'high_security':
            return SupportedCurves.P384
        elif use_case == 'performance':
            return SupportedCurves.P256
        else:  # general case
            return SupportedCurves.P256
    
    @staticmethod
    def get_curve_compatibility_info(curve: SupportedCurves):
        """
        Get compatibility information for a curve
        
        Returns:
            dict: Compatibility information
        """
        compatibility = {
            SupportedCurves.P256: {
                'browsers': 'Excellent',
                'mobile': 'Excellent', 
                'government': 'Approved',
                'libraries': 'Universal'
            },
            SupportedCurves.P384: {
                'browsers': 'Good',
                'mobile': 'Good',
                'government': 'Approved',
                'libraries': 'Wide'
            },
            SupportedCurves.SECP256K1: {
                'browsers': 'Limited',
                'mobile': 'Limited',
                'government': 'Not approved',
                'libraries': 'Specialized'
            }
        }
        
        return compatibility.get(curve, {})


# Curve selection utility functions
def get_curve_by_name(curve_name: str) -> SupportedCurves:
    """
    Get curve by name string
    
    Args:
        curve_name: Name of the curve ('P-256', 'P-384', etc.)
        
    Returns:
        SupportedCurves: The matching curve
        
    Raises:
        ValueError: If curve name is not found
    """
    for curve in SupportedCurves:
        if curve.value['name'].lower() == curve_name.lower():
            return curve
    
    raise ValueError(f"Unsupported curve: {curve_name}")


def list_available_curves():
    """
    List all available curves with their information
    
    Returns:
        dict: Dictionary of curve names and their information
    """
    curves_info = {}
    for curve in SupportedCurves:
        curves_info[curve.value['name']] = curve.value
    
    return curves_info


def get_security_comparison():
    """
    Get security level comparison of all curves
    
    Returns:
        dict: Security comparison data
    """
    comparison = {}
    for curve in SupportedCurves:
        comparison[curve.value['name']] = {
            'security_bits': curve.value['security_level'],
            'key_size': curve.value['key_size'],
            'performance': curve.value['performance'],
            'recommended': curve.value['recommended']
        }
    
    return comparison
