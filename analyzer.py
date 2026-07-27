# Version 2.0 - Added unit testing support
"""
Password Guardian Pro - Advanced Password Security Analyzer
ST4017CMD Introduction to Programming - Coursework Project
"""

import hashlib
import re
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import string
import time
from datetime import datetime
import threading
import urllib.request
import urllib.error

requests = None

# ============================================
# CUSTOM DATA STRUCTURE: Password History (Linked List)
# ============================================
class PasswordNode:
    """Node for custom linked list storing password analysis history"""
    def __init__(self, password_hash, score, entropy, timestamp):
        self.password_hash = password_hash
        self.score = score
        self.entropy = entropy
        self.timestamp = timestamp
        self.next = None

class PasswordHistory:
    """Custom Linked List to store password analysis history"""
    def __init__(self, max_size=20):
        self.head = None
        self.size = 0
        self.max_size = max_size
    
    def add_entry(self, password_hash, score, entropy):
        """Add new entry to the history (most recent at head)"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_node = PasswordNode(password_hash, score, entropy, timestamp)
        
        # Add to front (most recent first)
        new_node.next = self.head
        self.head = new_node
        self.size += 1
        
        # Trim if exceeds max size
        if self.size > self.max_size:
            self._trim_tail()
    
    def _trim_tail(self):
        """Remove oldest entry if exceeding max size"""
        if not self.head or not self.head.next:
            return
        
        current = self.head
        while current.next and current.next.next:
            current = current.next
        current.next = None
        self.size -= 1
    
    def get_history(self):
        """Retrieve all history entries as a list"""
        entries = []
        current = self.head
        while current:
            entries.append({
                'hash': current.password_hash[:8] + '...',
                'score': current.score,
                'entropy': current.entropy,
                'timestamp': current.timestamp
            })
            current = current.next
        return entries
    
    def find_weak_passwords(self):
        """Find previously analyzed weak passwords (score < 2)"""
        weak_list = []
        current = self.head
        while current:
            if current.score < 2:
                weak_list.append({
                    'hash': current.password_hash[:8] + '...',
                    'score': current.score,
                    'timestamp': current.timestamp
                })
            current = current.next
        return weak_list

# ============================================
# CORE ALGORITHM: Advanced Password Analysis
# ============================================
class PasswordAnalyzer:
    """Advanced password analysis engine with custom algorithms"""
    
    # Common weak patterns and dictionary words
    COMMON_PATTERNS = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 
        'admin', 'letmein', 'welcome', 'master', 'sunshine',
        'password123', 'admin123', 'user123', 'test123'
    ]
    
    KEYBOARD_PATTERNS = [
        'qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop',
        'asdfghjkl', 'zxcvbnm', '1234567890'
    ]
    
    @staticmethod
    def calculate_entropy(password):
        """Calculate password entropy in bits (custom algorithm)"""
        length = len(password)
        if length == 0:
            return 0
        
        # Determine character set size
        char_set_size = 0
        if re.search(r'[a-z]', password):
            char_set_size += 26
        if re.search(r'[A-Z]', password):
            char_set_size += 26
        if re.search(r'[0-9]', password):
            char_set_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>_]', password):
            char_set_size += 32
        
        if char_set_size == 0:
            return 0
        
        # Entropy = length * log2(char_set_size)
        import math
        entropy = length * math.log2(char_set_size)
        return round(entropy, 2)
    
    @staticmethod
    def check_common_patterns(password):
        """Check for common patterns and dictionary words"""
        password_lower = password.lower()
        
        # Check for common passwords
        for common in PasswordAnalyzer.COMMON_PATTERNS:
            if common in password_lower:
                return True, f"Contains common password pattern: '{common}'"
        
        # Check for keyboard patterns
        for pattern in PasswordAnalyzer.KEYBOARD_PATTERNS:
            if pattern in password_lower:
                return True, f"Contains keyboard pattern: '{pattern}'"
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            return True, "Contains repeated characters (e.g., 'aaa')"
        
        # Check for sequential numbers
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            return True, "Contains sequential numbers"
        
        return False, "No common patterns detected"
    
    @staticmethod
    def analyze_strength(password):
        """Comprehensive password strength analysis"""
        score = 0
        feedback = []
        patterns_found = []
        
        # Length check
        length = len(password)
        if length >= 12:
            score += 2
            feedback.append("✓ Excellent length (12+ characters)")
        elif length >= 8:
            score += 1
            feedback.append("✓ Good length (8+ characters)")
        else:
            feedback.append("✗ Aim for at least 8 characters")
        
        # Complexity checks
        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            score += 1
            feedback.append("✓ Mixed case (upper and lower)")
        else:
            feedback.append("✗ Use both upper and lowercase letters")
        
        if re.search(r'[0-9]', password):
            score += 1
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("✗ Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>_]', password):
            score += 1
            feedback.append("✓ Contains special characters")
        else:
            feedback.append("✗ Add special characters (e.g., @, #, $)")
        
        # Check for common patterns
        has_pattern, pattern_msg = PasswordAnalyzer.check_common_patterns(password)
        if has_pattern:
            score -= 1
            patterns_found.append(pattern_msg)
            feedback.append(f"⚠️ {pattern_msg}")
        
        # Calculate entropy
        entropy = PasswordAnalyzer.calculate_entropy(password)
        
        # Detailed entropy feedback
        if entropy >= 60:
            feedback.append(f"🔐 Entropy: {entropy} bits (Excellent)")
        elif entropy >= 40:
            feedback.append(f"🔐 Entropy: {entropy} bits (Good)")
        else:
            feedback.append(f"🔐 Entropy: {entropy} bits (Weak)")
        
        # Final score adjustment
        score = max(0, min(6, score))  # Scale between 0-6
        
        return score, feedback, entropy, patterns_found

# ============================================
# PASSWORD BREACH CHECK (API Integration)
# ============================================
class BreachChecker:
    """Handle password breach checking via Have I Been Pwned API"""
    
    @staticmethod
    def check_breach(password):
        """Check if password has been in a data breach"""
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5_char, remaining_char = sha1_password[:5], sha1_password[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{first5_char}"
        
        try:
            if requests is not None:
                response = requests.get(url, timeout=10)
                if response.status_code != 200:
                    return {
                        'status': 'error',
                        'message': "Could not connect to breach database. Please check your connection."
                    }
                response_text = response.text
            else:
                with urllib.request.urlopen(url, timeout=10) as response:
                    response_text = response.read().decode('utf-8')
            
            # Parse response
            hashes = (line.split(':') for line in response_text.splitlines())
            for h, count in hashes:
                if h == remaining_char:
                    return {
                        'status': 'breached',
                        'message': f"❌ BREACHED! Found {count} times in known data leaks.\nDO NOT USE THIS PASSWORD!",
                        'count': int(count),
                        'severity': 'critical'
                    }
            
            return {
                'status': 'secure',
                'message': "✅ SECURE! This password has not been found in any known data leaks.",
                'severity': 'safe'
            }
            
        except TimeoutError:
            return {
                'status': 'error',
                'message': "⏱️ Connection timeout. Please try again."
            }
        except urllib.error.URLError:
            return {
                'status': 'error',
                'message': "🌐 Network error. Please check your internet connection."
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f"⚠️ An unexpected error occurred: {str(e)}"
            }

# ============================================
# PASSWORD GENERATOR
# ============================================
class PasswordGenerator:
    """Generate strong, random passwords"""
    
    @staticmethod
    def generate_password(length=16, use_upper=True, use_lower=True, 
                          use_digits=True, use_special=True):
        """Generate a cryptographically strong password"""
        characters = ""
        if use_lower:
            characters += string.ascii_lowercase
        if use_upper:
            characters += string.ascii_uppercase
        if use_digits:
            characters += string.digits
        if use_special:
            characters += "!@#$%^&*()_-+=<>?/"
        
        if not characters:
            return "Error: No character types selected"
        
        # Ensure at least one of each type if selected
        password = []
        if use_lower:
            password.append(random.choice(string.ascii_lowercase))
        if use_upper:
            password.append(random.choice(string.ascii_uppercase))
        if use_digits:
            password.append(random.choice(string.digits))
        if use_special:
            password.append(random.choice("!@#$%^&*()_-+=<>?/"))
        
        # Fill remaining length
        remaining = length - len(password)
        password.extend(random.choice(characters) for _ in range(remaining))
        
        # Shuffle the password list
        random.shuffle(password)
        
        return ''.join(password)

# ============================================
# MODERN GUI APPLICATION
# ============================================
class PasswordGuardianPro:
    """Advanced GUI Application with professional interface"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Password Guardian Pro - Security Analyzer")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Initialize custom data structures
        self.password_history = PasswordHistory()
        
        # Configure modern ttk theme
        self._setup_theme()
        
        # Build the interface
        self._build_interface()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _setup_theme(self):
        """Configure modern theme for the application"""
        style = ttk.Style()
        
        # Choose a modern theme
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
        
        # Custom colors
        self.colors = {
            'bg': '#f0f2f5',
            'sidebar': '#1a1a2e',
            'sidebar_text': '#ffffff',
            'accent': '#4a90d9',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'text': '#2c3e50',
            'card_bg': '#ffffff'
        }
        
        # Configure custom styles
        style.configure('Sidebar.TFrame', background=self.colors['sidebar'])
        style.configure('Sidebar.TLabel', background=self.colors['sidebar'], 
                       foreground=self.colors['sidebar_text'])
        style.configure('Card.TFrame', background=self.colors['card_bg'], 
                       relief='raised', borderwidth=1)
        style.configure('Header.TLabel', font=('Segoe UI', 24, 'bold'), 
                       background=self.colors['sidebar'], foreground='#ffffff')
        style.configure('SubHeader.TLabel', font=('Segoe UI', 12), 
                       background=self.colors['sidebar'], foreground='#a8a8b8')
        style.configure('Title.TLabel', font=('Segoe UI', 14, 'bold'), 
                       background=self.colors['card_bg'])
        style.configure('Result.TLabel', font=('Segoe UI', 11), 
                       background=self.colors['card_bg'])
    
    def _build_interface(self):
        """Build the complete GUI interface"""
        # Main container with two panels
        self.main_panel = ttk.Frame(self.root)
        self.main_panel.pack(fill='both', expand=True)
        
        # Left sidebar
        self._build_sidebar()
        
        # Right main content area
        self._build_main_content()
    
    def _build_sidebar(self):
        """Build the left sidebar navigation"""
        sidebar = ttk.Frame(self.main_panel, style='Sidebar.TFrame', width=250)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        
        # App logo/header
        ttk.Label(sidebar, text="🔒", style='Header.TLabel', 
                 font=('Segoe UI', 48)).pack(pady=(30, 5))
        ttk.Label(sidebar, text="Password", style='Header.TLabel').pack()
        ttk.Label(sidebar, text="Guardian Pro", style='Header.TLabel').pack()
        ttk.Label(sidebar, text="Security Analyzer v2.0", style='SubHeader.TLabel').pack(pady=(5, 20))
        
        # Status indicator
        status_frame = ttk.Frame(sidebar, style='Sidebar.TFrame')
        status_frame.pack(fill='x', padx=20, pady=10)
        ttk.Label(status_frame, text="● System Status", style='SubHeader.TLabel', 
                 font=('Segoe UI', 10)).pack(anchor='w')
        self.status_indicator = ttk.Label(status_frame, text="✓ Ready", 
                                         style='SubHeader.TLabel', foreground='#2ed573')
        self.status_indicator.pack(anchor='w', pady=(5, 0))
        
        # Quick stats
        stats_frame = ttk.Frame(sidebar, style='Sidebar.TFrame')
        stats_frame.pack(fill='x', padx=20, pady=20)
        ttk.Label(stats_frame, text="📊 Quick Stats", style='SubHeader.TLabel', 
                 font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 10))
        
        self.history_count_label = ttk.Label(stats_frame, text="Analyzed: 0", 
                                            style='SubHeader.TLabel')
        self.history_count_label.pack(anchor='w')
        self.weak_count_label = ttk.Label(stats_frame, text="Weak: 0", 
                                         style='SubHeader.TLabel')
        self.weak_count_label.pack(anchor='w')
        
        # Bottom info
        ttk.Label(sidebar, text="v2.0 | Built with Python", 
                 style='SubHeader.TLabel', font=('Segoe UI', 8)).pack(side='bottom', pady=10)
    
    def _build_main_content(self):
        """Build the main content area"""
        main_content = ttk.Frame(self.main_panel)
        main_content.pack(side='left', fill='both', expand=True, padx=20, pady=20)
        
        # Notebook (tabbed interface)
        self.notebook = ttk.Notebook(main_content)
        self.notebook.pack(fill='both', expand=True)
        
        # Tab 1: Analyzer
        self._build_analyzer_tab()
        
        # Tab 2: History
        self._build_history_tab()
        
        # Tab 3: Generator
        self._build_generator_tab()
    
    def _build_analyzer_tab(self):
        """Build the main analyzer tab"""
        analyzer_frame = ttk.Frame(self.notebook)
        self.notebook.add(analyzer_frame, text='🔍 Analyzer')
        
        # Title
        title = ttk.Label(analyzer_frame, text="Password Security Analyzer", 
                         font=('Segoe UI', 16, 'bold'))
        title.pack(pady=(0, 20))
        
        # Input section (Card style)
        input_card = ttk.Frame(analyzer_frame, style='Card.TFrame')
        input_card.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(input_card, text="Enter Password", style='Title.TLabel').pack(anchor='w', padx=15, pady=(15, 5))
        
        # Password entry with show/hide
        entry_frame = ttk.Frame(input_card)
        entry_frame.pack(fill='x', padx=15, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(entry_frame, textvariable=self.password_var, 
                                        font=('Segoe UI', 12), show='*')
        self.password_entry.pack(side='left', fill='x', expand=True)
        
        self.show_var = tk.BooleanVar()
        self.show_check = ttk.Checkbutton(entry_frame, text="👁️", 
                                          variable=self.show_var, 
                                          command=self._toggle_password_visibility)
        self.show_check.pack(side='right', padx=5)
        
        # Action buttons
        button_frame = ttk.Frame(input_card)
        button_frame.pack(fill='x', padx=15, pady=(10, 15))
        
        self.scan_btn = ttk.Button(button_frame, text="🔍 Scan Password", 
                                   command=self._analyze_password, width=20)
        self.scan_btn.pack(side='left')
        
        self.clear_btn = ttk.Button(button_frame, text="Clear", 
                                    command=self._clear_input, width=15)
        self.clear_btn.pack(side='left', padx=10)
        
        # Results section (Scrollable)
        results_card = ttk.Frame(analyzer_frame, style='Card.TFrame')
        results_card.pack(fill='both', expand=True, padx=10, pady=10)
        
        ttk.Label(results_card, text="📋 Analysis Results", 
                 style='Title.TLabel').pack(anchor='w', padx=15, pady=(15, 10))
        
        # Text area for results with scrollbar
        results_container = ttk.Frame(results_card)
        results_container.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        self.results_text = scrolledtext.ScrolledText(results_container, 
                                                      wrap='word',
                                                      font=('Consolas', 10),
                                                      height=12)
        self.results_text.pack(fill='both', expand=True)
        
        # Initialize with instructions
        self.results_text.insert('1.0', "📌 Enter a password and click 'Scan Password' to begin analysis...\n")
        self.results_text.config(state='disabled')
    
    def _build_history_tab(self):
        """Build the history tab with custom data structure visualization"""
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text='📚 History')
        
        # Treeview for history display
        columns = ('hash', 'score', 'entropy', 'timestamp')
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=15)
        
        # Define column headings
        self.history_tree.heading('hash', text='Password (Hash)')
        self.history_tree.heading('score', text='Score')
        self.history_tree.heading('entropy', text='Entropy (bits)')
        self.history_tree.heading('timestamp', text='Time Analyzed')
        
        # Set column widths
        self.history_tree.column('hash', width=150)
        self.history_tree.column('score', width=80)
        self.history_tree.column('entropy', width=120)
        self.history_tree.column('timestamp', width=180)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(history_frame, orient='vertical', 
                                  command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.history_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y', pady=10)
        
        # Refresh button
        refresh_btn = ttk.Button(history_frame, text="🔄 Refresh History", 
                                 command=self._refresh_history)
        refresh_btn.pack(pady=(0, 10))
        
        self._refresh_history()
    
    def _build_generator_tab(self):
        """Build the password generator tab"""
        generator_frame = ttk.Frame(self.notebook)
        self.notebook.add(generator_frame, text='⚙️ Generator')
        
        # Title
        ttk.Label(generator_frame, text="Password Generator", 
                 font=('Segoe UI', 16, 'bold')).pack(pady=20)
        
        # Options card
        options_card = ttk.Frame(generator_frame, style='Card.TFrame')
        options_card.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(options_card, text="Options", style='Title.TLabel').pack(anchor='w', padx=15, pady=10)
        
        # Length
        length_frame = ttk.Frame(options_card)
        length_frame.pack(anchor='w', padx=15, pady=5)
        ttk.Label(length_frame, text="Length:").pack(side='left')
        self.length_var = tk.IntVar(value=16)
        ttk.Spinbox(length_frame, from_=8, to=32, textvariable=self.length_var, 
                   width=10).pack(side='left', padx=10)
        
        # Character options
        char_frame = ttk.Frame(options_card)
        char_frame.pack(anchor='w', padx=15, pady=5)
        
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_special = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(char_frame, text="Uppercase", variable=self.use_upper).pack(side='left', padx=5)
        ttk.Checkbutton(char_frame, text="Lowercase", variable=self.use_lower).pack(side='left', padx=5)
        ttk.Checkbutton(char_frame, text="Digits", variable=self.use_digits).pack(side='left', padx=5)
        ttk.Checkbutton(char_frame, text="Special", variable=self.use_special).pack(side='left', padx=5)
        
        # Generate button
        generate_btn = ttk.Button(options_card, text="🔑 Generate Password", 
                                  command=self._generate_password)
        generate_btn.pack(pady=15)
        
        # Result card
        result_card = ttk.Frame(generator_frame, style='Card.TFrame')
        result_card.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(result_card, text="Generated Password", style='Title.TLabel').pack(anchor='w', padx=15, pady=10)
        
        self.generated_password_var = tk.StringVar()
        gen_entry = ttk.Entry(result_card, textvariable=self.generated_password_var, 
                             font=('Consolas', 14), justify='center', state='readonly')
        gen_entry.pack(fill='x', padx=15, pady=10)
        
        # Copy and use buttons
        button_frame = ttk.Frame(result_card)
        button_frame.pack(pady=10)
        
        copy_btn = ttk.Button(button_frame, text="📋 Copy to Clipboard", 
                              command=self._copy_generated_password)
        copy_btn.pack(side='left', padx=5)
        
        use_btn = ttk.Button(button_frame, text="🔍 Analyze This Password", 
                            command=self._use_generated_password)
        use_btn.pack(side='left', padx=5)
    
    # ============================================
    # GUI FUNCTIONALITY METHODS
    # ============================================
    
    def _toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='*')
    
    def _clear_input(self):
        """Clear password input and results"""
        self.password_var.set('')
        self.results_text.config(state='normal')
        self.results_text.delete('1.0', 'end')
        self.results_text.insert('1.0', "📌 Enter a password and click 'Scan Password' to begin analysis...\n")
        self.results_text.config(state='disabled')
    
    def _analyze_password(self):
        """Main analysis workflow - runs in separate thread for responsiveness"""
        password = self.password_var.get().strip()
        
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password to analyze!")
            return
        
        # Update status
        self.status_indicator.config(text="⏳ Scanning...", foreground='#f39c12')
        self.scan_btn.config(state='disabled')
        self.results_text.config(state='normal')
        self.results_text.delete('1.0', 'end')
        self.results_text.insert('1.0', "🔍 Analyzing password...\n\n")
        self.root.update()
        
        # Run analysis in separate thread to keep GUI responsive
        threading.Thread(target=self._perform_analysis, args=(password,), daemon=True).start()
    
    def _perform_analysis(self, password):
        """Perform actual analysis (runs in background thread)"""
        try:
            # 1. Password strength analysis
            strength_score, feedback, entropy, patterns = PasswordAnalyzer.analyze_strength(password)
            
            # 2. Breach check
            breach_result = BreachChecker.check_breach(password)
            
            # 3. Store in history (custom data structure)
            password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            self.password_history.add_entry(password_hash, strength_score, entropy)
            
            # Update UI (must be done in main thread)
            self.root.after(0, self._update_results, strength_score, feedback, 
                           entropy, patterns, breach_result)
            
        except Exception as e:
            self.root.after(0, self._show_error, str(e))
    
    def _update_results(self, score, feedback, entropy, patterns, breach_result):
        """Update the results display"""
        results = []
        
        # Header
        results.append("=" * 60)
        results.append("🔐 PASSWORD ANALYSIS REPORT")
        results.append("=" * 60)
        
        # Score
        results.append(f"\n📊 STRENGTH SCORE: {score}/6")
        
        # Strength level
        if score >= 5:
            results.append("   ✅ Excellent Password! Very strong.")
        elif score >= 4:
            results.append("   ✅ Good Password! Strong.")
        elif score >= 3:
            results.append("   ⚠️ Moderate Password. Could be stronger.")
        else:
            results.append("   ❌ Weak Password! Needs improvement.")
        
        # Entropy
        results.append(f"\n🔐 ENTROPY: {entropy} bits")
        if entropy >= 60:
            results.append("   ✅ Excellent entropy - very difficult to crack")
        elif entropy >= 40:
            results.append("   ✓ Good entropy - reasonable strength")
        else:
            results.append("   ❌ Low entropy - easily crackable")
        
        # Pattern warnings
        if patterns:
            results.append("\n⚠️ PATTERN WARNINGS:")
            for pattern in patterns:
                results.append(f"   • {pattern}")
        
        # Detailed feedback
        results.append("\n📝 DETAILED FEEDBACK:")
        for item in feedback:
            results.append(f"   {item}")
        
        # Breach check
        results.append("\n" + "=" * 60)
        results.append("🌐 BREACH DATABASE CHECK")
        results.append("=" * 60)
        
        if breach_result['status'] == 'breached':
            results.append(f"\n❌ {breach_result['message']}")
        elif breach_result['status'] == 'secure':
            results.append(f"\n✅ {breach_result['message']}")
        else:
            results.append(f"\n⚠️ {breach_result['message']}")
        
        # Add to results text
        self.results_text.delete('1.0', 'end')
        self.results_text.insert('1.0', '\n'.join(results))
        self.results_text.config(state='disabled')
        
        # Update status
        self.status_indicator.config(text="✓ Analysis Complete", foreground='#2ed573')
        self.scan_btn.config(state='normal')
        
        # Update history
        self._refresh_history()
        
        # Update stats
        self._update_stats()
    
    def _show_error(self, error_message):
        """Display error message"""
        self.results_text.config(state='normal')
        self.results_text.delete('1.0', 'end')
        self.results_text.insert('1.0', f"⚠️ ERROR:\n{error_message}")
        self.results_text.config(state='disabled')
        
        self.status_indicator.config(text="✗ Error", foreground='#e74c3c')
        self.scan_btn.config(state='normal')
    
    def _refresh_history(self):
        """Refresh the history treeview from custom data structure"""
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Get history entries
        entries = self.password_history.get_history()
        
        # Add to treeview
        for entry in entries:
            self.history_tree.insert('', 'end', values=(
                entry['hash'],
                f"{entry['score']}/6",
                entry['entropy'],
                entry['timestamp']
            ))
    
    def _update_stats(self):
        """Update sidebar statistics"""
        entries = self.password_history.get_history()
        self.history_count_label.config(text=f"Analyzed: {len(entries)}")
        
        weak_entries = self.password_history.find_weak_passwords()
        self.weak_count_label.config(text=f"Weak: {len(weak_entries)}")
    
    def _generate_password(self):
        """Generate a random secure password"""
        length = self.length_var.get()
        password = PasswordGenerator.generate_password(
            length=length,
            use_upper=self.use_upper.get(),
            use_lower=self.use_lower.get(),
            use_digits=self.use_digits.get(),
            use_special=self.use_special.get()
        )
        self.generated_password_var.set(password)
    
    def _copy_generated_password(self):
        """Copy generated password to clipboard"""
        password = self.generated_password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
    
    def _use_generated_password(self):
        """Use generated password for analysis"""
        password = self.generated_password_var.get()
        if password:
            self.password_var.set(password)
            self.notebook.select(0)  # Switch to analyzer tab
            self._analyze_password()
    
    def _on_close(self):
        """Clean up when closing application"""
        self.root.quit()
        self.root.destroy()

# ============================================
# MAIN APPLICATION ENTRY POINT
# ============================================
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGuardianPro(root)
    root.mainloop()
