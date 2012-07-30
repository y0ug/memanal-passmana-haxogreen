PAPER=MemoryAnalysis_PasswordManager

all: $(PAPER).pdf

$(PAPER).dvi: $(PAPER).tex
	latex $^
	latex $^

$(PAPER).ps: $(PAPER).dvi
	dvips $^

$(PAPER).pdf: $(PAPER).ps
	ps2pdf $^

clean:
	rm -f *.aux *.dvi *.ps *.log *.nav *.snm *.toc *.out *.vrb

cleanall: clean
	rm -f *.pdf
