import google.auth
import requests
from django.contrib.auth import get_user_model
# utils.py
import os
from io import BytesIO
from datetime import datetime
from django.conf import settings
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib import colors
from reportlab.lib.units import inch

def generate_rental_agreement_pdf(agreement):
    """
    Generate a PDF rental agreement document and save it to the media directory.
    Returns the path to the generated PDF file.
    """
    # Create the media directory if it doesn't exist
    os.makedirs(settings.MEDIA_ROOT, exist_ok=True)
    agreements_dir = os.path.join(settings.MEDIA_ROOT, 'rental_agreements')
    os.makedirs(agreements_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"rental_agreement_{agreement.agreement_id}_{timestamp}.pdf"
    filepath = os.path.join(agreements_dir, filename)
    
    # Create PDF document
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=72)
    
    # Styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Center', alignment=TA_CENTER))
    styles.add(ParagraphStyle(name='Left', alignment=TA_LEFT))
    styles.add(ParagraphStyle(name='Title', fontSize=18, leading=22, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name='Header', fontSize=14, leading=18, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name='Subheader', fontSize=12, leading=16))
    styles.add(ParagraphStyle(name='BodyText', fontSize=10, leading=12))
    
    # Content
    story = []
    
    # Header
    story.append(Paragraph("JAMHURI YA MUUNGANO WA TANZANIA", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("MKATABA WA KUKODISHA SHAMBA", styles["Header"]))
    story.append(Paragraph("(Farm Rental Agreement)", styles["Subheader"]))
    story.append(Spacer(1, 24))
    
    # Agreement Info
    agreement_info = [
        [Paragraph("<b>Namba ya Mkataba:</b>", styles["BodyText"]), 
         Paragraph(agreement.agreement_id, styles["BodyText"])],
        [Paragraph("<b>Tarehe:</b>", styles["BodyText"]), 
         Paragraph(agreement.agreement_date.strftime("%d/%m/%Y"), styles["BodyText"])],
        [Paragraph("<b>Muda wa Mkataba:</b>", styles["BodyText"]), 
         Paragraph(f"{agreement.duration_months} Miezi", styles["BodyText"])],
    ]
    
    agreement_table = Table(agreement_info, colWidths=[2*inch, 3*inch])
    agreement_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (0,0), (0,-1), 'LEFT'),
        ('ALIGN', (1,0), (1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(agreement_table)
    story.append(Spacer(1, 24))
    
    # Parties Section
    story.append(Paragraph("WAHUSIKA WA MKATABA", styles["Header"]))
    story.append(Spacer(1, 12))
    
    # Landlord Info
    landlord_data = [
        [Paragraph("<b>MKODISHAJI (LANDLORD):</b>", styles["Subheader"])],
        [Paragraph(f"<b>Jina:</b> {agreement.landlord_name}", styles["BodyText"])],
        [Paragraph(f"<b>Simu:</b> {agreement.landlord_phone}", styles["BodyText"])],
        [Paragraph(f"<b>Barua Pepe:</b> {agreement.landlord_email}", styles["BodyText"])],
        [Paragraph(f"<b>Makazi:</b> {agreement.landlord_residence}", styles["BodyText"])],
    ]
    
    # Tenant Info
    tenant_data = [
        [Paragraph("<b>MKODISHWA (TENANT):</b>", styles["Subheader"])],
        [Paragraph(f"<b>Jina:</b> {agreement.tenant_name}", styles["BodyText"])],
        [Paragraph(f"<b>Simu:</b> {agreement.tenant_phone}", styles["BodyText"])],
        [Paragraph(f"<b>Barua Pepe:</b> {agreement.tenant_email}", styles["BodyText"])],
        [Paragraph(f"<b>Makazi:</b> {agreement.tenant_residence}", styles["BodyText"])],
    ]
    
    parties_table = Table([
        [Table(landlord_data), Table(tenant_data)]
    ], colWidths=[3*inch, 3*inch])
    
    parties_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(parties_table)
    story.append(Spacer(1, 24))
    
    # Property Details
    story.append(Paragraph("MAELEZO YA SHAMBA", styles["Header"]))
    story.append(Spacer(1, 12))
    
    property_data = [
        [Paragraph("<b>Eneo:</b>", styles["BodyText"]), Paragraph(agreement.farm_location, styles["BodyText"])],
        [Paragraph("<b>Ukubwa:</b>", styles["BodyText"]), Paragraph(f"{agreement.farm_size} Ekari", styles["BodyText"])],
        [Paragraph("<b>Aina ya Udongo:</b>", styles["BodyText"]), Paragraph(agreement.farm_quality, styles["BodyText"])],
        [Paragraph("<b>Aina ya Shamba:</b>", styles["BodyText"]), Paragraph(agreement.farm_type, styles["BodyText"])],
    ]
    
    if agreement.farm_description:
        property_data.append([
            Paragraph("<b>Maelezo Ziada:</b>", styles["BodyText"]), 
            Paragraph(agreement.farm_description, styles["BodyText"])
        ])
    
    property_table = Table(property_data, colWidths=[1.5*inch, 4.5*inch])
    property_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (0,0), (0,-1), 'LEFT'),
        ('ALIGN', (1,0), (1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(property_table)
    story.append(Spacer(1, 24))
    
    # Financial Terms
    story.append(Paragraph("MASHARTI YA KIFEDHA", styles["Header"]))
    story.append(Spacer(1, 12))
    
    financial_data = [
        [Paragraph("<b>Kodi ya Mwezi:</b>", styles["BodyText"]), 
         Paragraph(f"TZS {agreement.monthly_rent:,.2f}", styles["BodyText"])],
        [Paragraph("<b>Dhamana:</b>", styles["BodyText"]), 
         Paragraph(f"TZS {agreement.deposit_amount:,.2f}", styles["BodyText"])],
        [Paragraph("<b>Malipo ya Awali:</b>", styles["BodyText"]), 
         Paragraph(f"TZS {agreement.initial_payment:,.2f}", styles["BodyText"])],
    ]
    
    financial_table = Table(financial_data, colWidths=[2*inch, 3*inch])
    financial_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (0,0), (0,-1), 'LEFT'),
        ('ALIGN', (1,0), (1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(financial_table)
    story.append(Spacer(1, 24))
    
    # Terms and Conditions
    story.append(Paragraph("MASHARTI NA HALI", styles["Header"]))
    story.append(Spacer(1, 12))
    
    terms = [
        f"1. Mkataba huu utadumu kwa muda wa miezi {agreement.duration_months}.",
        "2. Kodi ya kila mwezi itakuwa TZS {:,.2f} na itatakiwa ilipwe mwanzoni mwa kila mwezi.".format(agreement.monthly_rent),
        "3. Mkodishwa atalipa dhamana ya TZS {:,.2f} ambayo itarudishwa mwishoni mwa mkataba.".format(agreement.deposit_amount),
        "4. Mkodishwa hataruhusiwa kubadilisha matumizi ya shamba bila idhini ya mkodishaji.",
        "5. Mkataba huu unaweza kukatishwa kwa maelewano ya pande zote mbili.",
        "6. Sheria za Tanzania zitatumika katika utatuzi wa mizozo yoyote."
    ]
    
    for term in terms:
        story.append(Paragraph(term, styles["BodyText"]))
        story.append(Spacer(1, 6))
    
    story.append(Spacer(1, 24))
    
    # Signatures
    story.append(Paragraph("SAHIHI ZA WAHUSIKA", styles["Header"]))
    story.append(Spacer(1, 12))
    
    signatures_data = [
        [
            Paragraph("<b>MKODISHAJI:</b>", styles["BodyText"]),
            Paragraph("<b>MKODISHWA:</b>", styles["BodyText"])
        ],
        [
            Paragraph("Sahihi: _________________________", styles["BodyText"]),
            Paragraph("Sahihi: _________________________", styles["BodyText"])
        ],
        [
            Paragraph(f"Tarehe: {datetime.now().strftime('%d/%m/%Y')}", styles["BodyText"]),
            Paragraph("Tarehe: __________________", styles["BodyText"])
        ],
        [
            Paragraph("<b>SHAHIDI WA KWANZA:</b>", styles["BodyText"]),
            Paragraph("<b>SHAHIDI WA PILI:</b>", styles["BodyText"])
        ],
        [
            Paragraph("Jina: _________________________", styles["BodyText"]),
            Paragraph("Jina: _________________________", styles["BodyText"])
        ],
        [
            Paragraph("Sahihi: _________________________", styles["BodyText"]),
            Paragraph("Sahihi: _________________________", styles["BodyText"])
        ],
    ]
    
    signatures_table = Table(signatures_data, colWidths=[3*inch, 3*inch])
    signatures_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(signatures_table)
    
    # Build the PDF
    doc.build(story)
    
    # Save the PDF to file
    with open(filepath, 'wb') as f:
        f.write(buffer.getvalue())
    
    # Return relative path from MEDIA_ROOT
    return filepath

def verify_google_token(token):
    try:
        # Verifying token with Google
        response = requests.get(f'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token}')
        user_info = response.json()

        if response.status_code != 200:
            raise ValueError("Invalid Google token")

        return user_info
    except Exception as e:
        raise ValueError("Invalid Google token") from e

def some_user_function():
    User = get_user_model()
    user = User.objects.filter(is_active=True).first()
    if not user:
        raise ValueError("No active user found in the database.")
    return user.id
