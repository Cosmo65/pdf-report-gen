# generate json files about data from different sources
# Then create pdf from it

from reportlab.pdfgen import canvas
from reportlab.graphics.charts.piecharts import Pie
import logging
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4, LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm, cm
from reportlab.platypus import *
from reportlab.rl_config import defaultPageSize
from reportlab.lib.colors import HexColor
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.doughnut import *
from reportlab.graphics.charts.barcharts import *
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.textlabels import Label
from datetime import date
from math import floor, ceil

from gather_info import *

from logging.config import dictConfig
from logging.handlers import SysLogHandler

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

fields = []
styles = getSampleStyleSheet()
ParaStyle = styles["Normal"]
WIDTH = defaultPageSize[0]
HEIGHT = defaultPageSize[1]


#CommonData adds page number and header to every page at the footer on bottom right corner
class CommonData(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        """add page info to each page (page x of y)"""
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            self.add_logo()
            self.drawString(5, HEIGHT-70, "VSS - Security Overview Report")
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.setFont("Helvetica", 7)
        self.drawRightString(200*mm, 20*mm,
            "Page %d of %d" % (self._pageNumber, page_count))
    
    def add_logo(self):
        self.drawImage("images/vmware_logo.jpg", 20*mm, 20*mm, width=1.5*inch, height=0.24*inch)


# Add VSS image on the first page. Cna be replaced with custom image by providing the file in same location.
# Try to use a ".jpeg" image
def on_first_page(canvas, doc):
    canvas.saveState()
    canvas.drawImage("images/vss.jpeg", 20*mm, HEIGHT-200,width=6.5*inch, height=1.06*inch)
    canvas.setFont('Times-Bold', 20)
    canvas.drawCentredString(WIDTH/2.0, HEIGHT - 350, "Security Overview Report")
    canvas.setFont('Times-Roman', 14)
    company = get_org_name()
    canvas.drawCentredString(WIDTH/2.0, HEIGHT/2.0-(100), "For: " + company)
    canvas.setFillColor(HexColor("#696969"))
    canvas.setFont('Times-Roman', 12)
    today = date.today()
    today_formatted = today.strftime("%b-%d-%Y")
    canvas.drawCentredString(WIDTH/2.0, HEIGHT/2.0-(120), "Generated On: " + today_formatted)
    canvas.restoreState()
        
def add_para(txt, style=ParaStyle, klass=Paragraph, sep=0.1):
    s = Spacer(0, sep*inch)
    para = klass(txt, style)
    sect = [s, para]
    result = KeepTogether(sect)
    return result

def add_aws_cis_doughnut_chart():
    drawing = Drawing(doc.width/2-18, doc.height/2-45)
    donut = Doughnut()
    donut.data = [[10, 90]]
    donut.slices[0].fillColor = colors.blue
    donut.slices[1].fillColor = colors.lightgrey
    donut.slices.strokeColor = colors.white
    donut.innerRadiusFraction = 0.75
    drawing.add(donut)
    fields.append(drawing)
    
def add_compliance_risk_overview():
    frame_aws_cis = Frame(doc.leftMargin, doc.topMargin+270, doc.width/2-6, doc.height/2-30, id='doughnut1', showBoundary=0)
    frame_azure_cis = Frame(doc.leftMargin+doc.width/2+6, doc.rightMargin+270, doc.width/2-6,
                doc.height/2-30, id='doughtnut2', showBoundary=0)
    fields.append(NextPageTemplate("TwoDonuts"))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2, doc.height/2, add_aws_cis_doughnut_chart(), mode='shrink'))

    return frame_aws_cis, frame_azure_cis
    
def add_risk_score_vs_object_count_chart():
    drawing = Drawing(doc.width, doc.height/2)
    risk_scores = [(100, 35, 40, 70, 100, 55, 43, 22, 21, 81, 5)]
    bar = VerticalBarChart()
    bar.x = 0
    bar.y = 0
    bar.height = doc.height/2
    bar.width = doc.width
    bar.barWidth = 4
    bar.barSpacing = 1
    bar.data = risk_scores
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = max(risk_scores[0]) * 1.2 ## graph display 1.2 times as much as max 
    bar.valueAxis.valueStep = int(ceil(max(risk_scores[0])/40))*10 ## Convert to neartest 10
    bar.categoryAxis.categoryNames = ["1-100", "101-200", "201-300", "301-400", "401-500","501-600","601-700", "701-800",
                                      "801-900", "901-1000", ">1000"]
    bar.categoryAxis.labels.dx = 0
    #bar.categoryAxis.labels.dy = -2
    bar.categoryAxis.labels.angle = 45
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.bars[0].fillColor = colors.green
    bar.categoryAxis.labels.boxAnchor = 'ne'
    drawing.add(bar)
    fields.append(drawing)
    

def add_top_10_objects_by_risk():
    fields.append(add_para("<br></br><br></br>"))
    fields.append(add_para("<br></br><br></br>"))
    data = [["Risk Score", "Finding Count", "Object Type", "Object ID", "Provider", "Cloud Account"], [980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781],
            [980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781], [980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781],
            [980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781],[980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781],
            [980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781],[980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781],
            [980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781],[980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781],
            [980, 5, "EC2", "ec2-036eqhbda767adg", "AWS", 73762781]]
    rs_table = Table(data, [80,80,80,120,60,80], 30, repeatRows=1)
    rs_table.hAlign = "CENTER"
    rs_table.vAlign = "MIDDLE"
    rs_table.setStyle(TableStyle([   
                       ('BACKGROUND', (0,0), (-1, 0), HexColor("#3498eb")),
                       ('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    fields.append(rs_table)
    

def add_asset_risk_overview():
    fields.append(add_para("<br></br><br></br>"))
    fields.append(Paragraph("4.3. Asset Risk Overview", style=styles["Heading3"]))
    fields.append(add_para("List of objects with the highest risk score. Shows the objects with the highest risk."))
    fields.append(add_para("There are 1872 assets out of 15072 assets that have violations across 92 accounts."))
    add_risk_score_vs_object_count_chart()
    add_top_10_objects_by_risk()
    
# Adds Exectuive summary section
def add_executive_summary_section():
    
    fields.append(Paragraph("Executive Summary", style=styles["Heading1"]))
    fields.append(Paragraph("1. Introduction", style=styles["Heading3"]))
    account_info = get_account_info()
    text = '''This report contains cloud configuration security assessment results from ''' + str(account_info["accounts"]) + ''' cloud accounts across your environment. 
    The cloud environment was evaluated across ''' + str(account_info["rules"]) + ''' rules associated with ''' + str(account_info["compliance_frameworks"]) + ''' compliance frameworks. 
    There were ''' + str(account_info["total_violations"]) + ''' violations found.<br/><br/> 
    
    This analysis provides summaries and breakdowns to help address the risk identified, along with change comparison since last evaluation. 
    The findings are generated by comprehensive evaluation through a revolutionary inter-connected security model that identifies in-depth configuration problems.'''
    
    info = add_para(text)
    fields.append(info)

def add_scope_section():
    fields.append(Paragraph("2. Scope", style=styles["Heading3"]))
    config = get_config()
    
    text = '''
    The scope of this report is within the context of the following filters:<br/>
    Provider: 		AWS, Azure<br/>
    Cloud Accounts: All 	(472 accounts)<br/>
    Frameworks: 	All 	(9 frameworks)<br/>
    Severity: 		High<br/>
    Cloud Tag: 		All<br/>
    Environment:	All<br/>
    '''
    info = add_para(text)
    fields.append(info)


def add_findings_by_provider_chart():
    drawing = Drawing(300, 200)
    data = get_findings_by_provider()
    maxVal = max(data[0])
    
    bar = HorizontalBarChart()
    bar.x = 30
    bar.y = 0
    bar.height = 150
    bar.width = 400
    bar.data = data
    bar.strokeColor = colors.white
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = maxVal*2   ## graph displa twice as much as max violation
    bar.valueAxis.valueStep = int(ceil(maxVal/400))*100  ## Convert to neartest 100
    bar.categoryAxis.labels.boxAnchor = 'ne'
    bar.categoryAxis.labels.dx = -10
    bar.categoryAxis.labels.dy = -2
    bar.categoryAxis.labels.fontName = 'Helvetica'
    bar.categoryAxis.categoryNames = ["AWS", "Azure"]
    bar.bars[(0,0)].fillColor = HexColor("#f5990f")
    bar.bars[(0,1)].fillColor = HexColor("#3a32a8")
    bar.barWidth = 5
    bar.barSpacing = 0.1
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15

    drawing.add(bar)
  #  add_legend(drawing, bar)
    yLabel = Label()
    yLabel.setText("Number of Findings ---->")
    yLabel.fontSize = 12
    yLabel.fontName = 'Helvetica'
    yLabel.dx = 250
    yLabel.dy = -30
    
    chartLabel = Label()
    chartLabel.setText("Findings by Provider")
    chartLabel.fontSize = 14
    chartLabel.fontName = 'Helvetica'
    chartLabel.dx = 250
    chartLabel.dy = 160
    
    drawing.add(chartLabel)
    drawing.add(yLabel)
    fields.append(drawing)


def add_cloud_security_overview_section():
    fields.append(Paragraph("3. Cloud Security Overview", style=styles["Heading3"]))
    fields.append(add_para("<br/><br/>"))
    data = [("Cloud Accounts", get_account_info()["accounts"]), ("Open Findings", get_open_resolved_findings()["open"]), ("Resolved Findings", get_open_resolved_findings()["resolved"]),\
            ("Rules Configured", get_account_info()["rules"]), ("High Severity Findings", get_account_info()["total_violations"]), ("Compliance Frameworks", 9)]
    b = Table(data, 150, 30)
    b.hAlign = "CENTER"
    b.vAlign = "MIDDLE"
    b.setStyle(TableStyle([   
                       ('BACKGROUND', (-1,0), (-1, -1), HexColor("#3498eb")),
                       ('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    fields.append(b)
    add_findings_by_provider_chart()

def add_top_10_rules():
    data = [["Rule", "Provider", "Object Type", "Cloud Account", "Severity", "Count"], [10,"AWS", "EC2", "12345", "High", 10], [10,"AWS", "EC2", "12345", "High", 10],
            [10,"Azure", "VM", "12345", "High", 10], [10,"Azure", "VM", "12345998", "Medium", 5], [10,"AWS", "EC2", "12345", "High", 10], [10,"AWS", "EC2", "12345", "High", 10],
            [56,"AWS", "EC2", "65417gaqgq", "Low", 10], [10,"AWS", "EC2", "12345", "Medium", 10], [10,"AWS", "EC2", "12345", "High", 10]]
    tb = Table(data, [80,80,80,80,80,80], 30, repeatRows=1)
    tb.hAlign = "CENTER"
    tb.vAlign = "MIDDLE"
    tb.setStyle(TableStyle([   
                       ('BACKGROUND', (0,0), (-1, 0), HexColor("#3498eb")),
                       ('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    #fields.append(FrameBreak())
    fields.append(tb)

def add_top_10_accounts_by_open_findings():

    sectionTable = Table([["Provider", "Cloud Account", "Open Findings", "Suppressed Findings"]], [80,120,120,120], 30)
    sectionTable.setStyle(TableStyle([   
                       ('BACKGROUND', (0,0), (-1, -1), HexColor("#3498eb")),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                       ('BOX',(0,0),(-1,-1),0.01*inch,colors.white),
                       ('FONTSIZE', (0,0), (-1,-1), 12),
                       ('TOPPADDING', (0,0),(-1,-1), 0),
                       ('BOTTOMPADDING', (0,0),(-1,-1), 0),
                       ('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    accountsTable = Table([["", "", "High", "Medium", "Low", ""], ["AWS", "123456", "5", "25", "10", "10"], ["AWS", "123456", "5", "25", "10", "10"], ["AWS", "123456", "5", "25", "10", "10"], ["Azure", "kjbajbdc7867482", "5", "25", "10", "10"]], [80,120,40,45,35,120], 30)
    
    accountsTable.setStyle(TableStyle([   
                       #('BACKGROUND', (-1,0), (-1, 0), HexColor("#3498eb")),
                       ('GRID',(0,0),(-1,-1),0.01*inch,colors.black),
                       ('SPAN', (0,0), (1,0)),
                       ('BOX',(0,0),(-1,-1),0.01*inch,colors.white),
                       #('LINEABOVE', (0,0),(0,-1), 0.01, colors.white),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                       ('TOPPADDING', (0,0),(-1,-1), 0),
                       ('BOTTOMPADDING', (0,0),(-1,-1), 0),
                       ('FONTSIZE', (0,0), (-1,-1), 10),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
     
    finalTable = Table([[sectionTable], [accountsTable]], 440)
    finalTable.setStyle(TableStyle([   
                       #('BACKGROUND', (-1,0), (-1, 0), HexColor("#3498eb")),
                       ('SPAN',(0,0),(-1,0)),
                       ('BOX',(0,0),(-1,-1),0.01*inch,colors.black),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       
                       ('FONTSIZE', (0,0), (-1,-1), 10),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))

    fields.append(finalTable)

def add_azure_top_10_rules_chart():
    drawing = Drawing(doc.width/2-18, doc.height/2-45)
    rules = [(10, 35, 30)]
    bar = VerticalBarChart()
    bar.x = 10
    bar.y = 60
    bar.height = doc.height/4
    bar.width = doc.width/2 - 40
    bar.barWidth = 2
    bar.barSpacing = 0.5
    bar.data = rules
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = max(rules[0]) * 1.5 ## graph displa twice as much as max violation
    bar.valueAxis.valueStep = int(ceil(max(rules[0])/40))*10 ## Convert to neartest 10
    bar.categoryAxis.categoryNames = ["high", "medium", "low"]
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.bars[0].fillColor = colors.blue
    bar.categoryAxis.labels.boxAnchor = 'n'
    drawing.add(bar)
    fields.append(drawing) 
    

def add_aws_top_10_rules_chart():
    drawing = Drawing(doc.width/2-18, doc.height/2-45)
    rules = [(100, 35, 40)]
    bar = VerticalBarChart()
    bar.x = 10
    bar.y = 60
    bar.height = doc.height/4
    bar.width = doc.width/2 - 40
    bar.barWidth = 2
    bar.barSpacing = 0.5
    bar.data = rules
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = max(rules[0]) * 1.5 ## graph displa twice as much as max violation
    bar.valueAxis.valueStep = int(ceil(max(rules[0])/40))*10 ## Convert to neartest 10
    bar.categoryAxis.categoryNames = ["high", "medium", "low"]
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.bars[0].fillColor = colors.orange
    bar.categoryAxis.labels.boxAnchor = 'n'
    drawing.add(bar)
    fields.append(drawing)

def add_rule_violations_by_provider_chart(doc):


    frame1 = Frame(doc.leftMargin, doc.height, doc.width, 80, id='row1', showBoundary=0)
    frame2 = Frame(doc.leftMargin, doc.topMargin+270, doc.width/2-6, doc.height/2-30, id='col1', showBoundary=0)
    frame3 = Frame(doc.leftMargin+doc.width/2+6, doc.rightMargin+270, doc.width/2-6,
               doc.height/2-30, id='col2', showBoundary=0)
    
    
    fields.append(NextPageTemplate('TwoCol'))
    fields.append(FrameBreak())
    fields.append(Paragraph("4.2 Rule Risk Overview", style=styles["Heading4"]))
    fields.append(add_para("A prioritized list of rule violations by cloud account. Shows the rule violations with the highest risk."))
    fields.append(add_para("There are 90872 open findings across 253 rules with 193 AWS and 60 Azure rules."))
    fields.append(FrameBreak())
    aws_logo = Image("images/aws-logo.jpg", width=30, height=30, hAlign='RIGHT')
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2-30,add_aws_top_10_rules_chart(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2, add_azure_top_10_rules_chart(), mode='shrink'))
    #fields.append(FrameBreak())
    return frame1, frame2, frame3

def add_cloud_account_risk_overview_section():
    fields.append(Paragraph("4. Risk Overview", style=styles["Heading3"]))
    fields.append(Paragraph("4.1 Cloud Account Risk Overview", style=styles["Heading4"]))
    open_resolve = get_open_resolved_findings()
    account_info = get_account_info()
    text = ''' There are ''' + str(open_resolve["open"]) + ''' open findings and ''' + str(open_resolve["resolved"]) + ''' resolved findings across ''' + str(account_info["accounts"]) + ''' accounts.
    '''
    fields.append(add_para(text))
    add_findings_by_account_chart()
    add_top_10_accounts_by_open_findings()


def add_findings_by_account_chart():
    drawing = Drawing(500, 500)
    findings, accounts = get_top_10_accounts_by_findings()
    open_maxVal = max(findings[0])
    resolve_maxVal = max(findings[1])
    maxVal = max(open_maxVal, resolve_maxVal)   ## Find maximum number of findings open or resolved and use it as basis for plotting the graph
    
    bar = HorizontalBarChart()
    bar.x = 25
    bar.y = -10
    bar.height = 500
    bar.width = 450
    bar.data = findings
    bar.strokeColor = colors.white
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = maxVal*1.5  ## graph display 1.5 times as much as max violation
    bar.valueAxis.valueStep = int(ceil(maxVal/4000))*1000  ## Convert to neartest 100
    bar.categoryAxis.labels.boxAnchor = 'ne'
    bar.categoryAxis.labels.dx = -10
    bar.categoryAxis.labels.dy = -2
    bar.categoryAxis.labels.fontName = 'Helvetica'
    bar.categoryAxis.categoryNames = accounts
    bar.bars[0].fillColor = HexColor("#3a32a8")
    bar.bars[1].fillColor = colors.gray
    bar.barWidth = 5
    bar.barSpacing = 0.5
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    
    drawing.add(bar)
    fields.append(drawing)
    newPage()
    
def newPage():
    fields.append(PageBreak())

# Creates the initial report document
def init_report():
    doc = SimpleDocTemplate("vss_compliance_report.pdf", pagesize=LETTER)
    return doc

def build_report(document):
    document.build(fields, canvasmaker=CommonData)
    logging.info("Successfully generated report !!\n")

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    logging.info("Generating Report ...")
    auth()
    gather_data()
    doc = init_report()  
    frameFirstPage = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
    fields.append(FrameBreak())
    add_executive_summary_section()
    add_scope_section()
    newPage()
    add_cloud_security_overview_section()
    newPage()
    add_cloud_account_risk_overview_section()

    
    frame1, frame2, frame3 = add_rule_violations_by_provider_chart(doc)
    doc.addPageTemplates([PageTemplate(id='OneCol', frames=[frameFirstPage], onPage=on_first_page),
                      PageTemplate(id='TwoCol',frames=[frame1, frame2, frame3]),
                      ])
    
    add_top_10_rules()
    add_asset_risk_overview()
    frame_aws_cis, frame_azure_cis = add_compliance_risk_overview()
    doc.addPageTemplates([PageTemplate(id='TwoDonuts',frames=[frame_aws_cis, frame_azure_cis])])
    
    build_report(doc)
