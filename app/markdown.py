from markdown_pdf import MarkdownPdf, Section

pdf = MarkdownPdf(toc_level=2)

def markdown_to_pdf(markdown):
    return pdf.add_section(Section(markdown))