import os
import re
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    A canvas that enables two-pass rendering to dynamically compute and display
    running headers and footers with accurate total page count.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        # Cover page (Page 1) doesn't get headers/footers
        if self._pageNumber == 1:
            self.saveState()
            # Draw a modern, decorative vertical bar on the left margin of the cover page
            self.setFillColor(colors.HexColor('#1e3a8a')) # Deep blue accent
            self.rect(0, 0, 18, 792, fill=True, stroke=False)
            self.restoreState()
            return

        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor('#64748b')) # Slate gray
        
        # Header
        self.drawString(54, 750, "Security Dashboard - Project Files Detail Report")
        self.setLineWidth(0.5)
        self.setStrokeColor(colors.HexColor('#cbd5e1'))
        self.line(54, 742, 558, 742)
        
        # Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 40, page_text)
        self.drawString(54, 40, "Confidential - Security Dashboard Architecture Review")
        self.line(54, 52, 558, 52)
        
        self.restoreState()


def analyze_content(filename, content, file_type):
    """
    Parses file contents to automatically extract functional architecture details,
    such as imports, classes, functions, templates dependencies, form endpoints, etc.
    """
    analysis = {
        'purpose': '',
        'imports': [],
        'classes': [],
        'functions': [],
        'routes': [],
        'key_elements': {}
    }
    
    if file_type == 'Python':
        # Extract imports
        imports = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                imports.append(line)
        analysis['imports'] = imports
        
        # Extract classes
        classes = []
        class_matches = re.finditer(r'class\s+(\w+)(?:\(([^)]+)\))?:', content)
        for m in class_matches:
            class_name = m.group(1)
            bases = m.group(2) or ''
            classes.append(f"{class_name}({bases})" if bases else class_name)
        analysis['classes'] = classes
        
        # Extract functions/methods
        functions = []
        func_matches = re.finditer(r'def\s+(\w+)\s*\(([^)]*)\):', content)
        for m in func_matches:
            func_name = m.group(1)
            params = m.group(2).strip()
            # Clean up parameters slightly (remove excessive whitespace)
            params = re.sub(r'\s+', ' ', params)
            functions.append(f"{func_name}({params})")
        analysis['functions'] = functions
        
        # Extract Flask routes in app.py
        if filename == 'app.py':
            routes = []
            route_matches = re.finditer(r'@app\.route\(\s*[\'"]([^\'"]+)[\'"](?:,\s*methods=\[([^\]]+)\])?\)', content)
            for m in route_matches:
                path = m.group(1)
                methods = m.group(2) or "'GET'"
                methods = methods.replace("'", "").replace('"', '').strip()
                routes.append(f"{path} [{methods}]")
            analysis['routes'] = routes
            
        # Hardcode rich descriptions of files to make the report highly descriptive
        if filename == 'app.py':
            analysis['purpose'] = "The core application server handling web controller operations. It manages Flask routing, session management, OAuth authentication (GitHub & Google), database setup, and page renders for all dashboard panels and security tools."
        elif filename == 'models.py':
            analysis['purpose'] = "Contains the SQLAlchemy database schemas. It models the core application entities, specifically: Users (for auth), Alerts (for logging tool findings), ScanHistory (to store user checks), and FileLog (for file encryption events)."
        elif filename == 'security_tools.py':
            analysis['purpose'] = "Encapsulates the core business logic for security utilities: password strength computation, URL trust checks, network socket port scanners, and symmetric file encryption/decryption using cryptography modules."
            
    elif file_type == 'HTML':
        # Check if extends base.html
        extends = '{% extends' in content
        
        # Find block names
        blocks = re.findall(r'{%\s*block\s+(\w+)\s*%}', content)
        
        # Find form actions
        forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', content)
        
        analysis['key_elements'] = {
            'extends': extends,
            'blocks': list(set(blocks)),
            'forms': list(set(forms))
        }
        
        # Set description based on file name
        if filename == 'base.html':
            analysis['purpose'] = "Common layout template providing standard HTML wrapper structure. Contains navbar navigation, alert flash alerts, links to styles, standard JS scripts, and template blocks."
        elif filename == 'index.html':
            analysis['purpose'] = "The landing home page. Explains features, presents marketing hero graphics, and shows CTA action points to sign in or register."
        elif filename == 'dashboard.html':
            analysis['purpose'] = "Central hub user page. Visualizes overall counts (alerts, safe URLs, today's scans) with premium metrics cards and lists active security alerts/scan history timelines."
        elif filename == 'login.html':
            analysis['purpose'] = "Renders user credential login fields and provides integration redirects for OAuth providers (Google and GitHub)."
        elif filename == 'register.html':
            analysis['purpose'] = "Presents user sign-up inputs validating matching password fields."
        elif filename == 'alerts.html':
            analysis['purpose'] = "Alert logs panel, categorizing risk incidents by severity (high, medium, low) using color badges."
        elif filename == 'password_analyzer.html':
            analysis['purpose'] = "Frontend interface for password strength analyzer. Displays visual score indicators, weakness lists, and requirements."
        elif filename == 'url_checker.html':
            analysis['purpose'] = "Interface for domain checks. Submits target domains to analyze connection encryption and phishing key factors."
        elif filename == 'port_scanner.html':
            analysis['purpose'] = "Dashboard tool for scanning open ports on target servers. Displays risk alerts for typically open service ports."
        elif filename == 'file_encryption.html':
            analysis['purpose'] = "Secure file encryption/decryption panel. Handles uploads, outputs hex data representations, and downloads processed results."

    elif file_type == 'CSS':
        rules_count = content.count('{')
        analysis['key_elements'] = {
            'rules_count': rules_count
        }
        analysis['purpose'] = "Central style sheet file formatting custom layouts, glassmorphism cards, dashboard grids, colors, and keyframe animations."
        
    elif file_type == 'Markdown':
        headers = []
        for line in content.splitlines():
            if line.startswith('#'):
                headers.append(line.strip('# '))
        analysis['key_elements'] = {
            'headers': headers
        }
        analysis['purpose'] = "Standard project documentation specifying installation steps, features list, and setup instructions."
        
    elif file_type == 'Requirements':
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                packages.append(line)
        analysis['key_elements'] = {
            'packages': packages
        }
        analysis['purpose'] = "System dependencies management configuration file. Pinned libraries facilitate DB access, Bcrypt hashing, OAuth authentication, and symmetric key encryption."

    return analysis


def gather_file_info(root_dir):
    file_list = []
    # Folders to skip
    skip_dirs = {'venv', '__pycache__', '.git', '.idea', 'artifacts', 'scratch'}
    # Files to skip
    skip_files = {'database.db', 'project_files_detail_report.pdf', 'generate_pdf.py'}

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Modify in place to skip specified directories
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in filenames:
            if filename in skip_files:
                continue
            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, root_dir)
            rel_path_forward_slashes = rel_path.replace('\\', '/')
            
            size_bytes = os.path.getsize(full_path)
            line_count = 0
            is_binary = False
            content = ""
            
            # Binary extension checks
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.ico', '.gif', '.db')):
                is_binary = True
            else:
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        line_count = len(lines)
                        content = "".join(lines)
                except Exception:
                    is_binary = True
            
            # Determine file type
            file_type = 'Unknown'
            if '.' in filename:
                ext = filename.split('.')[-1].lower()
                if ext == 'py':
                    file_type = 'Python'
                elif ext == 'html':
                    file_type = 'HTML'
                elif ext == 'css':
                    file_type = 'CSS'
                elif ext == 'md':
                    file_type = 'Markdown'
                elif ext == 'txt' and filename == 'requirements.txt':
                    file_type = 'Requirements'
                else:
                    file_type = ext.upper()
            else:
                if filename == 'requirements.txt':
                    file_type = 'Requirements'
            
            structures = analyze_content(filename, content, file_type)
            
            file_list.append({
                'name': filename,
                'rel_path': rel_path_forward_slashes,
                'size': size_bytes,
                'lines': line_count,
                'is_binary': is_binary,
                'type': file_type,
                'structures': structures
            })
            
    # Custom sort sorting python files first, then HTML, CSS, Markdown, and others
    def sort_key(f):
        path_lower = f['rel_path'].lower()
        if path_lower.endswith('.py'):
            return (0, path_lower)
        elif 'templates/' in path_lower:
            return (1, path_lower)
        elif path_lower.endswith('.css'):
            return (2, path_lower)
        elif path_lower.endswith('.md'):
            return (3, path_lower)
        else:
            return (4, path_lower)
            
    file_list.sort(key=sort_key)
    return file_list


def build_pdf(root_dir, output_path):
    files = gather_file_info(root_dir)
    
    # Calculate stats
    total_files = len(files)
    total_lines = sum(f['lines'] for f in files if not f['is_binary'])
    total_bytes = sum(f['size'] for f in files)
    
    file_types = {}
    for f in files:
        t = f['type']
        file_types[t] = file_types.get(t, 0) + 1
        
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=72,
        bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    
    # Define color scheme
    primary_color = colors.HexColor('#1e293b')   # Deep Slate Blue
    accent_color = colors.HexColor('#1e3a8a')    # Dark Blue
    text_color = colors.HexColor('#334155')      # Muted Slate text
    code_color = colors.HexColor('#0f172a')      # Code font black
    border_color = colors.HexColor('#cbd5e1')    # Light gray borders
    bg_header_color = colors.HexColor('#f1f5f9') # Light slate table background
    
    # Custom Paragraph Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=34,
        textColor=primary_color,
        spaceAfter=12
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=30
    )
    
    section_title_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=primary_color,
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    subsection_title_style = ParagraphStyle(
        'SubSectionHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#2563eb'), # Modern bright blue
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=text_color,
        spaceAfter=8
    )
    
    meta_label_style = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=primary_color
    )
    
    meta_value_style = ParagraphStyle(
        'MetaValue',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=text_color
    )
    
    meta_value_code_style = ParagraphStyle(
        'MetaValueCode',
        parent=styles['Normal'],
        fontName='Courier-Bold',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#b91c1c') # Crimson red for code values
    )
    
    bullet_style = ParagraphStyle(
        'BulletText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=text_color,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )
    
    code_bullet_style = ParagraphStyle(
        'CodeBulletText',
        parent=bullet_style,
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=code_color
    )
    
    story = []
    
    # ------------------ COVER PAGE ------------------
    story.append(Spacer(1, 40))
    story.append(Paragraph("Security Dashboard", title_style))
    story.append(Paragraph("Workspace Source Files Detail Report", subtitle_style))
    story.append(Spacer(1, 15))
    
    # Add project overview
    story.append(Paragraph("<b>Project Overview</b>", subsection_title_style))
    overview_text = (
        "This report compiles technical details, architectural structural lists, and purposes "
        "for all source files located in the Security Dashboard workspace. "
        "The project is a Flask-based web application providing security tools: a password analyzer, "
        "URL checker, network socket port scanner, and file encryption using Fernet symmetric encryption. "
        "It includes local SQLite storage (SQLAlchemy) and dual OAuth client capabilities."
    )
    story.append(Paragraph(overview_text, body_style))
    story.append(Spacer(1, 20))
    
    # Summary Statistics Table
    story.append(Paragraph("<b>Project Metrics</b>", subsection_title_style))
    summary_data = [
        [Paragraph("Metadata Metric", meta_label_style), Paragraph("Value Detail", meta_label_style)],
        [Paragraph("Report Generation Date", body_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), body_style)],
        [Paragraph("Target Workspace Directory", body_style), Paragraph(root_dir, body_style)],
        [Paragraph("Total Tracked Files", body_style), Paragraph(str(total_files), body_style)],
        [Paragraph("Total Lines of Code (Source)", body_style), Paragraph(f"{total_lines:,}", body_style)],
        [Paragraph("Total Workspace Size", body_style), Paragraph(f"{total_bytes / 1024:.2f} KB ({total_bytes:,} bytes)", body_style)],
    ]
    summary_table = Table(summary_data, colWidths=[180, 324])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), bg_header_color),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 25))
    
    # File Type breakdown table
    story.append(Paragraph("<b>File Type Breakdown</b>", subsection_title_style))
    type_data = [[Paragraph("File Type / Extension", meta_label_style), Paragraph("Count", meta_label_style)]]
    for ext, count in sorted(file_types.items()):
        type_data.append([Paragraph(ext, body_style), Paragraph(str(count), body_style)])
        
    type_table = Table(type_data, colWidths=[250, 254])
    type_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), bg_header_color),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(type_table)
    story.append(PageBreak())
    
    # ------------------ INDIVIDUAL FILE SECTIONS ------------------
    for file_info in files:
        # File Title header
        story.append(Paragraph(file_info['rel_path'], section_title_style))
        story.append(Spacer(1, 5))
        
        # File Metadata Table
        meta_rows = [
            [Paragraph("File Path", meta_label_style), Paragraph(file_info['rel_path'], meta_value_code_style)],
            [Paragraph("File Size", meta_label_style), Paragraph(f"{file_info['size']:,} bytes ({file_info['size']/1024:.2f} KB)", meta_value_style)],
            [Paragraph("Line Count", meta_label_style), Paragraph(str(file_info['lines']) if not file_info['is_binary'] else 'N/A (Binary Asset)', meta_value_style)],
            [Paragraph("File Type", meta_label_style), Paragraph(file_info['type'], meta_value_style)],
        ]
        meta_table = Table(meta_rows, colWidths=[120, 384])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), bg_header_color),
            ('GRID', (0,0), (-1,-1), 0.5, border_color),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))
        
        # Purpose Description
        story.append(Paragraph("<b>File Description:</b>", subsection_title_style))
        purpose = file_info['structures'].get('purpose', '')
        if not purpose:
            if file_info['is_binary']:
                purpose = "Binary graphic resource. Used as visual layout brand asset."
            else:
                purpose = "Standard text configuration file containing parameters or raw documentation."
        story.append(Paragraph(purpose, body_style))
        story.append(Spacer(1, 8))
        
        # Structure Details block
        struct = file_info['structures']
        
        # PYTHON FILES details
        if file_info['type'] == 'Python':
            # Imports
            if struct.get('imports'):
                story.append(Paragraph("<b>Import Dependencies:</b>", subsection_title_style))
                for imp in struct['imports']:
                    story.append(Paragraph(f"• {imp}", code_bullet_style))
                story.append(Spacer(1, 8))
                
            # Classes
            if struct.get('classes'):
                story.append(Paragraph("<b>Classes Defined:</b>", subsection_title_style))
                for cls in struct['classes']:
                    story.append(Paragraph(f"• class {cls}", code_bullet_style))
                story.append(Spacer(1, 8))
                
            # Functions
            if struct.get('functions'):
                story.append(Paragraph("<b>Functions and Methods:</b>", subsection_title_style))
                for func in struct['functions']:
                    story.append(Paragraph(f"• def {func}", code_bullet_style))
                story.append(Spacer(1, 8))
                
            # Flask Routes
            if struct.get('routes'):
                story.append(Paragraph("<b>Flask Routing Endpoints:</b>", subsection_title_style))
                for r in struct['routes']:
                    story.append(Paragraph(f"• {r}", code_bullet_style))
                story.append(Spacer(1, 8))
                
        # HTML FILES details
        elif file_info['type'] == 'HTML':
            elem = struct.get('key_elements', {})
            if elem:
                story.append(Paragraph("<b>HTML Template Properties:</b>", subsection_title_style))
                extends_val = "Yes (extends <code>base.html</code>)" if elem.get('extends') else "No (root document)"
                story.append(Paragraph(f"• <b>Base Extension:</b> {extends_val}", bullet_style))
                
                blocks = elem.get('blocks')
                if blocks:
                    blocks_str = ", ".join(f"<code>{b}</code>" for b in blocks)
                    story.append(Paragraph(f"• <b>Layout Blocks:</b> {blocks_str}", bullet_style))
                    
                forms = elem.get('forms')
                if forms:
                    forms_str = ", ".join(f"<code>{f}</code>" for f in forms)
                    story.append(Paragraph(f"• <b>Form Endpoints:</b> {forms_str}", bullet_style))
                story.append(Spacer(1, 8))
                
        # CSS FILES details
        elif file_info['type'] == 'CSS':
            elem = struct.get('key_elements', {})
            if elem:
                story.append(Paragraph("<b>CSS Properties:</b>", subsection_title_style))
                rules = elem.get('rules_count', 0)
                story.append(Paragraph(f"• <b>CSS Styling Rules Count:</b> {rules}", bullet_style))
                story.append(Spacer(1, 8))
                
        # Markdown FILES details
        elif file_info['type'] == 'Markdown':
            elem = struct.get('key_elements', {})
            if elem and elem.get('headers'):
                story.append(Paragraph("<b>Document Sections:</b>", subsection_title_style))
                for header in elem['headers']:
                    story.append(Paragraph(f"• {header}", bullet_style))
                story.append(Spacer(1, 8))
                
        # Requirements FILES details
        elif file_info['type'] == 'Requirements':
            elem = struct.get('key_elements', {})
            if elem and elem.get('packages'):
                story.append(Paragraph("<b>Required Dependencies:</b>", subsection_title_style))
                for pkg in elem['packages']:
                    story.append(Paragraph(f"• {pkg}", code_bullet_style))
                story.append(Spacer(1, 8))
                
        story.append(PageBreak())
        
    # Remove the last pagebreak to avoid an empty trailing page
    if story and isinstance(story[-1], PageBreak):
        story.pop()
        
    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)


if __name__ == '__main__':
    workspace = os.path.abspath(os.path.dirname(__file__))
    output_pdf = os.path.join(workspace, "project_files_detail_report.pdf")
    print(f"Generating PDF report: {output_pdf}")
    build_pdf(workspace, output_pdf)
    print("PDF Generation complete!")
