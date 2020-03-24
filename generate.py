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
from reportlab.platypus.tableofcontents import TableOfContents
from datetime import date
from math import floor, ceil
import textwrap
from xml.sax.saxutils import escape
from reportlab.lib.validators import Auto

from gather_info import *

from logging.config import dictConfig
from logging.handlers import SysLogHandler

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

fields = []
styles = getSampleStyleSheet()
ParaStyle = styles["Normal"]
styleN = styles["BodyText"]
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
            if(self._pageNumber != 1):
                self.drawString(5, HEIGHT-70, "VSS - Security Overview Report")
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.setFont("Helvetica", 10)
        if(self._pageNumber != 1):
            self.drawRightString(200*mm, 10*mm,
                "Page %d of %d" % (self._pageNumber, page_count))
    
    def add_logo(self):
        self.drawImage("images/vmware_logo.jpg", 20*mm, 10*mm, width=1.0*inch, height=0.16*inch)


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
    bar.y = -45
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
    # fields.append(add_para("<br></br><br></br>"))
    # fields.append(add_para("<br></br><br></br>"))
    columns = ["Risk\nScore", "Finding\nCount", "Object Name", "Object ID", "Provider", "Cloud Account"]
    
    data = get_top_10_objects_by_risk()
    
    # Use escape to add escape characters 
    for d in data:
        d[2] = Paragraph(escape(d[2]), style = styles["BodyText"])
        d[3] = Paragraph(escape(d[3]), style = styles["BodyText"])
        d[5] = Paragraph(escape(d[5]), style = styles["BodyText"])

    data.insert(0, columns)
    rs_table = Table(data, [60,45,90,170,60,80], 80, repeatRows=1)
    rs_table.hAlign = "CENTER"
    rs_table.vAlign = "MIDDLE"
    rs_table.setStyle(TableStyle([   
                       #('BACKGROUND', (0,0), (-1, 0), HexColor("#3498eb")),
                       #('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,0), 'MIDDLE'),
                       ('VALIGN', (0,1), (-1,-1), 'TOP'),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    data_len = len(data)

    for each in range(data_len):
        if each % 2 == 0:
            bg_color = colors.whitesmoke #HexColor("#DCDCDC") 
        else:
            bg_color = colors.white
        rs_table.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
    
    rs_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), HexColor("#3a7c91"))]))
    rs_table.setStyle(TableStyle([('TEXTCOLOR', (0, 0), (-1, 0), colors.white)]))
    fields.append(rs_table)
    

def add_asset_risk_overview():
    fields.append(add_para("<br></br><br></br>"))
    fields.append(Paragraph("4.3. Asset Risk Overview", style=styles["Heading3"]))
    fields.append(add_para("List of objects with the highest risk score. Shows the objects with the highest risk."))
    fields.append(add_para("There are 1872 assets out of 15072 assets that have violations across 92 accounts."))
    add_risk_score_vs_object_count_chart()
    fields.append(newPage())
    add_top_10_objects_by_risk()
    
# Adds Executive summary section
def add_executive_summary_section():
    
    fields.append(Paragraph("Executive Summary", style=styles["Heading1"]))
    fields.append(Paragraph("1. Introduction", style=styles["Heading2"]))
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
    fields.append(Paragraph("3. Cloud Security Overview", style=styles["Heading2"]))
    fields.append(add_para("<br/><br/>"))
    aws_violations, azure_violations = get_all_violations_by_severity()
    high = aws_violations[0]+azure_violations[0]
    data = [("Cloud Accounts", get_account_info()["accounts"]), ("Open Findings", get_open_resolved_findings()["open"]), ("Resolved Findings", get_open_resolved_findings()["resolved"]),\
            ("Rules Configured", get_account_info()["rules"]), ("High Severity Findings", high), ("Compliance Frameworks", 9)]
    tb = Table(data, 150, 30)
    tb.hAlign = "CENTER"
    tb.vAlign = "MIDDLE"
    tb.setStyle(TableStyle([   
                       #('BACKGROUND', (-1,0), (-1, -1), HexColor("#3498eb")),
                       #('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    
    data_len = len(data)
    
    for each in range(data_len):
        if each % 2 == 0:
            bg_color = colors.lightgrey
        else:
            bg_color = colors.whitesmoke

        tb.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
    fields.append(tb)
    add_findings_by_provider_chart()

def add_top_10_rules():
    data = get_top_10_rules()
    columns = ["Rule", "Provider", "Object Type", "Severity", "Count"]
    for d in data:
        d[0] = Paragraph(d[0], style = styles["BodyText"])   
    data.insert(0, columns)
    tb = Table(data, [170,60,80,80,60], 30, repeatRows=1)
    tb.hAlign = "CENTER"
    tb.vAlign = "MIDDLE"
    tb.setStyle(TableStyle([   
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                       #('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    data_len = len(data)

    for each in range(data_len):
        if each % 2 == 0:
            bg_color =  colors.lightgrey #HexColor("#edf3f3") 
        else:
            bg_color = colors.whitesmoke
        tb.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
    
    tb.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), HexColor("#3a7c91"))]))
    tb.setStyle(TableStyle([('TEXTCOLOR', (0, 0), (-1, 0), colors.white)]))
    fields.append(tb)

def add_top_10_accounts_by_open_findings():

    sectionTable = Table([["Provider", "Cloud Account", "Open Findings", "Suppressed\nFindings"]], [70,170,120,80], 35)
    sectionTable.setStyle(TableStyle([   
                       ('BACKGROUND', (0,0), (-1, -1), HexColor("#3a7c91")),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                       ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                       ('FONTSIZE', (0,0), (-1,-1), 12),
                       #('TOPPADDING', (0,0),(-1,-1), -5),
                       #('BOTTOMPADDING', (0,0),(-1,-1), 0),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    data = get_high_med_low_top_10_violations()
    columns = ["", "", "High", "Medium", "Low", ""]
    for d in data:
        # Added to support word wrap for account IDs
        # In case of Azure, the subscription ID is long
        d[1] = Paragraph(d[1], style = styles["BodyText"])
    
    data.insert(0, columns)
    accountsTable = Table(data, [70,170,40,45,35,80], 35)

    accountsTable.setStyle(TableStyle([   
                       ('BACKGROUND', (0,0), (-1, 0), HexColor("#3a7c91")),    
                       #('SPAN', (0,0), (1,0)),
                       ('TEXTCOLOR', (2,0), (2,-1), colors.red),
                       ('TEXTCOLOR', (3,0), (3,-1), colors.darkorange),
                       ('TEXTCOLOR', (4,0), (4,-1), colors.orange),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                       ('FONTSIZE', (0,0), (-1,-1), 10),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    data_len = len(data)
    for each in range(data_len):
        if each % 2 == 0:
            bg_color = colors.whitesmoke
        else:
            bg_color = colors.white

        accountsTable.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
     
    finalTable = Table([[sectionTable], [accountsTable]], 440)
    finalTable.setStyle(TableStyle([   
                       ('SPAN',(0,0),(-1,0)),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),            
                       ('FONTSIZE', (0,0), (-1,-1), 10),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))

    fields.append(finalTable)

def add_azure_findings_by_severity_chart():
    drawing = Drawing(doc.width/2-18, doc.height/2-45)
    aws, azure  = get_all_violations_by_severity()
    rules = [azure]
    bar = VerticalBarChart()
    bar.x = 10
    bar.y = 70
    bar.height = doc.height/4
    bar.width = doc.width/2 - 40
    bar.barWidth = 2
    bar.barSpacing = 0.5
    bar.data = rules
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = int(max(rules[0]) * 1.5) ## graph displa twice as much as max violation
    bar.valueAxis.valueStep = int(ceil(max(rules[0])/400))*100 ## Convert to neartest 10
    bar.categoryAxis.categoryNames = ["high", "medium", "low"]
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.bars[0].fillColor = colors.blue
    bar.categoryAxis.labels.boxAnchor = 'n'
    
    chartLabel = Label()
    chartLabel.setText("Findings by Severity - Azure")
    chartLabel.fontSize = 10
    chartLabel.fontName = 'Helvetica'
    chartLabel.dx = doc.rightMargin
    chartLabel.dy = doc.height-80
    
    
    drawing.add(chartLabel)
    drawing.add(bar)
    fields.append(drawing) 
    

def add_aws_findings_by_severity_chart():
    drawing = Drawing(doc.width/2-18, doc.height/2-45)
    aws, azure  = get_all_violations_by_severity()
    rules = [aws]
    bar = VerticalBarChart()
    bar.x = 10
    bar.y = 70
    bar.height = doc.height/4
    bar.width = doc.width/2 - 40
    bar.barWidth = 2
    bar.barSpacing = 0.5
    bar.data = rules
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = int(max(rules[0])*1.5) ## graph displa twice as much as max violation
    bar.valueAxis.valueStep = int(ceil(max(rules[0])/400))*100 ## Convert to neartest 10
    bar.categoryAxis.categoryNames = ["high", "medium", "low"]
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.bars[0].fillColor = colors.orange
    bar.categoryAxis.labels.boxAnchor = 'n'
    drawing.add(bar)
    fields.append(drawing)

def add_rule_violations_by_provider_chart(doc):

    frame1 = Frame(doc.leftMargin, doc.height, doc.width, 90, id='summary', showBoundary=0)
    frame2 = Frame(doc.leftMargin, doc.height-70, doc.width/2-40, 50, id='aws logo', showBoundary=0)
    frame3 = Frame(doc.leftMargin+doc.width/2+6, doc.height-70, doc.width/2-40, 50, id='azure logo', showBoundary=0)
    frame4 = Frame(doc.leftMargin, doc.topMargin+270, doc.width/2-6, doc.height/2-30, id='aws chart', showBoundary=0)
    frame5 = Frame(doc.leftMargin+doc.width/2+6, doc.rightMargin+270, doc.width/2-6, doc.height/2-30, id='azure chart', showBoundary=0)
    frame6 = Frame(doc.leftMargin, doc.height/2-260, 480, 300, id='top 10 rule table', showBoundary=0)
    
    fields.append(NextPageTemplate('RuleRiskOverview'))
    fields.append(FrameBreak())
    fields.append(Paragraph("4.2 Rule Risk Overview", style=styles["Heading3"]))
    fields.append(add_para("A prioritized list of rule violations by cloud account. Shows the rule violations with the highest risk."))
    text = "There are " + str(get_open_resolved_findings()["open"]) + " open findings after evaluating "+ str(get_account_info()["rules"]) + " rules across AWS and Azure."
    fields.append(add_para(text))
    fields.append(FrameBreak())
    aws_logo = Image("images/aws-logo.jpg", width=30, height=30, hAlign='RIGHT')
    fields.append(KeepTogether(aws_logo))
    fields.append(FrameBreak())
    azure_logo = Image("images/azure-logo.jpg", width=30, height=30, hAlign='RIGHT')
    fields.append(KeepTogether(azure_logo))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2-30,add_aws_findings_by_severity_chart(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2, add_azure_findings_by_severity_chart(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2, add_top_10_rules(), mode='shrink'))
    #fields.append(FrameBreak())
    return frame1, frame2, frame3, frame4, frame5, frame6

def add_cloud_account_risk_overview_section():
    fields.append(Paragraph("4. Risk Overview", style=styles["Heading2"]))
    fields.append(Paragraph("4.1 Cloud Account Risk Overview", style=styles["Heading3"]))
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
    length_accounts = len(accounts)
    for account in accounts:
        if(length_accounts > 0):
            idx = accounts.index(account)
            long_account_string = account
            if(len(long_account_string)>15):
                accounts.remove(account)
                account = textwrap.fill(account, 15)
                accounts.insert(idx,account)
            length_accounts = length_accounts - 1

    open_maxVal = max(findings[0])
    resolve_maxVal = max(findings[1])
    maxVal = max(open_maxVal, resolve_maxVal)   ## Find maximum number of findings open or resolved and use it as basis for plotting the graph
    
    bar = HorizontalBarChart()
    bar.x = 25
    bar.y = -25
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
    bar.bars[1].fillColor = colors.aqua
    bar.barWidth = 5
    bar.barSpacing = 0.5
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    
    legend = Legend()
    legend.alignment = 'right'
    legend.colorNamePairs = [[HexColor("#3a32a8"), "Open"], [colors.aqua, "Resolved"]]
    legend.columnMaximum = 2
    legend.x = 400
    legend.y = 470
    
    drawing.add(legend)
    
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

    
    # This is for Rule Risk Overview 
    frame1, frame2, frame3, frame4, frame5, frame6 = add_rule_violations_by_provider_chart(doc)
    doc.addPageTemplates([PageTemplate(id='OneCol', frames=[frameFirstPage], onPage=on_first_page),
                      PageTemplate(id='RuleRiskOverview',frames=[frame1, frame2, frame3, frame4, frame5, frame6])])
    
    add_asset_risk_overview()
    
    # Compliance Overview
    frame_aws_cis, frame_azure_cis = add_compliance_risk_overview()
    doc.addPageTemplates([PageTemplate(id='TwoDonuts',frames=[frame_aws_cis, frame_azure_cis])])
    
    
    build_report(doc)