# services/pdf_generator.py
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.units import inch
from reportlab.lib import colors
from io import BytesIO
import os
from django.conf import settings

class RentalAgreementPDFGenerator:
    def __init__(self, agreement_data):
        self.data = agreement_data
        
    def generate_pdf(self):
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch)
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], 
                                   alignment=TA_CENTER, fontSize=16, spaceAfter=12)
        subtitle_style = ParagraphStyle('CustomSubtitle', parent=styles['Heading2'], 
                                      alignment=TA_CENTER, fontSize=14, spaceAfter=8)
        normal_style = styles['Normal']
        
        story = []
        
        # Header
        story.append(Paragraph("JAMHURI YA MUUNGANO WA TANZANIA", title_style))
        story.append(Paragraph("MKATABA WA KUKODISHA SHAMBA", subtitle_style))
        story.append(Paragraph(f"Farm Rental Agreement - {self.data['agreement_id']}", normal_style))
        story.append(Spacer(1, 12))
        
        # Agreement details table
        agreement_info = [
            ['Agreement Date:', self.data['agreement_date'].strftime('%d/%m/%Y')],
            ['Farm Number:', self.data['farm_id']],
            ['Duration:', f"{self.data['duration_months']} months"],
        ]
        
        agreement_table = Table(agreement_info, colWidths=[2*inch, 3*inch])
        agreement_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(agreement_table)
        story.append(Spacer(1, 20))
        
        # Parties section
        story.append(Paragraph("WAHUSIKA WA MKATABA (PARTIES)", subtitle_style))
        
        parties_data = [
            ['MKODISHAJI (LANDLORD)', 'MKODISHWA (TENANT)'],
            [f"Name: {self.data['landlord_name']}", f"Name: {self.data['tenant_name']}"],
            [f"Phone: {self.data['landlord_phone']}", f"Phone: {self.data['tenant_phone']}"],
            [f"Email: {self.data['landlord_email']}", f"Email: {self.data['tenant_email']}"],
            [f"Address: {self.data['landlord_residence']}", f"Address: {self.data['tenant_residence']}"],
        ]
        
        parties_table = Table(parties_data, colWidths=[3*inch, 3*inch])
        parties_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(parties_table)
        story.append(Spacer(1, 20))
        
        # Farm details
        story.append(Paragraph("MAELEZO YA SHAMBA (FARM DETAILS)", subtitle_style))
        farm_details = [
            ['Location:', self.data['farm_location']],
            ['Size:', f"{self.data['farm_size']} Acres"],
            ['Soil Quality:', self.data['farm_quality']],
            ['Farm Type:', self.data['farm_type']],
            ['Description:', self.data.get('farm_description', 'N/A')],
        ]
        
        farm_table = Table(farm_details, colWidths=[2*inch, 4*inch])
        farm_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(farm_table)
        story.append(Spacer(1, 20))
        
        # Financial terms
        story.append(Paragraph("MASHARTI YA KIFEDHA (FINANCIAL TERMS)", subtitle_style))
        financial_details = [
            ['Monthly Rent:', f"TZS {self.data['monthly_rent']:,.2f}"],
            ['Security Deposit:', f"TZS {self.data['security_deposit']:,.2f}"],
            ['Advance Payment:', f"TZS {self.data['advance_payment']:,.2f}"],
            ['Total Initial Payment:', f"TZS {self.data['security_deposit'] + self.data['advance_payment']:,.2f}"],
        ]
        
        financial_table = Table(financial_details, colWidths=[2*inch, 3*inch])
        financial_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(financial_table)
        story.append(Spacer(1, 30))
        
        # Signature section
        story.append(Paragraph("SAHIHI NA MASHAHIDI (SIGNATURES & WITNESSES)", subtitle_style))
        
        signature_data = [
            ['MKODISHAJI (LANDLORD)', 'MKODISHWA (TENANT)'],
            ['Signature: ___________________', 'Signature: ___________________'],
            ['Date: ___________________', 'Date: ___________________'],
            ['', ''],
            ['SHAHIDI WA KWANZA (FIRST WITNESS)', 'SHAHIDI WA PILI (SECOND WITNESS)'],
            ['Name: ___________________', 'Name: ___________________'],
            ['Signature: ___________________', 'Signature: ___________________'],
        ]
        
        signature_table = Table(signature_data, colWidths=[3*inch, 3*inch])
        signature_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 4), (-1, 4), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(signature_table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer