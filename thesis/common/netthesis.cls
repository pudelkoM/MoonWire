%
% netthesis.cls
%
%

%----------------------------------------------------------------------
% Identify class
%
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{netthesis}%
    [2014/11/26 v0.01.0 %
    netthesis.cls NET thesis class %
    based on msvreport.cls]

%----------------------------------------------------------------------
% File encoding utf8x
%
%\RequirePackage{ucs}
%\RequirePackage[utf8x]{inputenc}

%----------------------------------------------------------------------
% Class options
%
\RequirePackage{kvoptions}%
\SetupKeyvalOptions{family=netthesis,prefix=netthesis@}%
% netcommon.sty
\DeclareVoidOption{ngerman}{\PassOptionsToPackage{netcommon}{ngerman}}%
\DeclareVoidOption{german}{\PassOptionsToPackage{netcommon}{german}}%
% netthesis.cls
\DeclareStringOption[plain]{document}
\DeclareVoidOption{dissertation}{\renewcommand\netthesis@document{dissertation}}
\DeclareVoidOption{bachelor}{\renewcommand\netthesis@document{bachelor}}
\DeclareVoidOption{master}{\renewcommand\netthesis@document{master}}
\DeclareVoidOption{idp}{\renewcommand\netthesis@document{idp}}
% Process options
\ProcessKeyvalOptions*\relax

%----------------------------------------------------------------------
% Load base class report and required packages
%
\LoadClassWithOptions{report}
\RequirePackage{geometry}
\RequirePackage{netcommon}
\RequirePackage{amsbsy}
\RequirePackage{amsmath}
\RequirePackage{amssymb}
\RequirePackage{amsthm}
\RequirePackage{setspace}
\RequirePackage{parskip}
%\RequirePackage{graphics}

%----------------------------------------------------------------------
% Do document specific things
%
\newcommand\@titlegerman{}
\newcommand\titlegerman[1]{%
    \isequal{#1}{\@empty}\ifequal\relax\else
        \renewcommand\@titlegerman{#1}%
    \fi
}
\newcommand\@titleenglish{}
\newcommand\titleenglish[1]{%
    \isequal{#1}{\@empty}\ifequal\relax\else
        \renewcommand\@titleenglish{#1}%
    \fi
}
\newcommand\@supervisor{}
\newcommand\supervisor[1]{%
    \isequal{#1}{\@empty}\ifequal\relax\else
        \renewcommand\@supervisor{#1}%
    \fi
}
\newcommand\@advisor{}
\newcommand\advisor[1]{%
    \isequal{#1}{\@empty}\ifequal\relax\else
        \renewcommand\@advisor{#1}%
    \fi
}

\newcommand\netthesis@titlepage{\netthesis@plaintitle}
\isequal{\netthesis@document}{dissertation}
\ifequal
    \renewcommand\netthesis@titlepage{\netthesis@dissertationtitle}
\fi
\isequal{\netthesis@document}{bachelor}
\ifequal
    \renewcommand\netthesis@titlepage{\netthesis@thesistitle}
    \newcommand\thesisdescription{Bachelor's Thesis in Informatics}
    \title{\@titleenglish}
    \ifnet@german
    	\title{\@titlegerman}
        \renewcommand\thesisdescription{Bachelor's Thesis in Informatik}
    \fi
\fi
\isequal{\netthesis@document}{master}
\ifequal
    \renewcommand\netthesis@titlepage{\netthesis@thesistitle}
    \newcommand\thesisdescription{Master's Thesis in Informatics}
    \title{\@titleenglish}
    \ifnet@german
    	\title{\@titlegerman}
        \renewcommand\thesisdescription{Master's Thesis in Informatik}
    \fi
\fi
\isequal{\netthesis@document}{idp}
\ifequal
    \renewcommand\netthesis@titlepage{\netthesis@thesistitle}
    \newcommand\thesisdescription{Interdisciplinary Project in Electrical Engineering}
    \title{\@titleenglish}
    \ifnet@german
    	\title{\@titlegerman}
        \renewcommand\thesisdescription{Interdisziplin{\"a}res Projekt in Elektrotechnik}
    \fi
\fi

\newcommand\authorstring{Author}
\newcommand\advisorstring{Advisor}
\newcommand\supervisorstring{Supervisor}
\newcommand\datestring{Date}
\ifnet@german
	\renewcommand\authorstring{Autor}
	\renewcommand\advisorstring{Betreuer}
	\renewcommand\supervisorstring{Aufgabensteller}
	\renewcommand\datestring{Datum}
\fi

%----------------------------------------------------------------------
% Page geometry
%
% textwidth
% 10pt (\@ptsize=0): 20pica -- 30pica
% 11pt (\@ptsize=1): 22pica -- 32pica
% 12pt (\@ptsize=2): 24pica -- 34pica
%
% margins for a4paper
% 10pt (\@ptsize=0):
% 11pt (\@ptsize=1):
% 12pt (\@ptsize=2):
%
\newlength\netthesis@linepc
\setlength\netthesis@linepc{28pc}
\ifisequal{\@ptsize}{0}
    \setlength\netthesis@linepc{30pc}
\fi
\ifisequal{\@ptsize}{1}
    \setlength\netthesis@linepc{32pc}
\fi
\ifisequal{\@ptsize}{2}
    \setlength\netthesis@linepc{34pc}
\fi
\geometry{text={\netthesis@linepc,1.618\netthesis@linepc}}
\if@twoside
    \geometry{marginratio={1:1,7:8}}
\else
    \geometry{marginratio={1:1,7:8}}
\fi
\linespread{1.1}

%----------------------------------------------------------------------
% Page styles
%
\if@twoside
    \newcommand\ps@report{%
        \let\@oddfoot\@empty\let\@evenfoot\@empty
        \def\@evenhead{\thepage\hfil\leftmark}%
        \def\@oddhead{{\rightmark}\hfil\thepage}%
        \let\@mkboth\markboth
        \def\chaptermark##1{%
            \markboth {{%\MakeUppercase{%
            \ifnum \c@secnumdepth >\m@ne
                \@chapapp\ \thechapter. \ %
            \fi
        ##1}}{}}%
        \def\sectionmark##1{%
            \markright {{%\MakeUppercase{%
            \ifnum \c@secnumdepth >\z@
                \thesection. \ %
            \fi
        ##1}}}%
    }
\else
    \newcommand\ps@report{%
        \let\@oddfoot\@empty
        \def\@oddhead{{\rightmark}\hfil\thepage}%
        \let\@mkboth\markboth
        \def\chaptermark##1{%
            \markright {{%\MakeUppercase{%
            \ifnum \c@secnumdepth >\m@ne
                \@chapapp\ \thechapter. \ %
            \fi
        ##1}}}%
    }
\fi
%\newcommand\ps@report{
%    \renewcommand\@oddhead{\hfill\thepage}%
%    \renewcommand\@evenhead{\thepage\hfill}%
%    \renewcommand\@oddfoot{}%
%    \renewcommand\@evenfoot{}%
%}
\newcommand\ps@reportchapter{
    \renewcommand\@oddhead{\hfill\thepage}%
    \renewcommand\@evenhead{\thepage\hfill}%
    \renewcommand\@oddfoot{}%
    \renewcommand\@evenfoot{}%
}
\newcommand\ps@reporttitle{
    \renewcommand\@oddhead{}%
    \renewcommand\@evenhead{}%
    \renewcommand\@oddfoot{}%
    \renewcommand\@evenfoot{}%
}
\pagestyle{report}

%----------------------------------------------------------------------
% Chapter and Section styles
%
\newcommand\netthesis@chapterfont{\huge}
\newcommand\netthesis@sectionfont{\Large}
\newcommand\netthesis@subsectionfont{\large}
\newcommand\netthesis@subsubsectionfont{\normalsize}
\newcommand\netthesis@paragraphfont{\normalsize\itshape}
\newcommand\netthesis@subparagraphfont{\normalsize}
\renewcommand\chapter{\net@chapter}
\newcommand\net@chapter{\clearpage\thispagestyle{empty}%
                    \if@openright\cleardoublepage\else\clearpage\fi%
                    \thispagestyle{reportchapter}%
                    \global\@topnum\z@
                    \@afterindentfalse
                    \secdef\@chapter\@schapter}
\def\@chapter[#1]#2{\ifnum \c@secnumdepth >\m@ne
                         \refstepcounter{chapter}%
                         \typeout{\@chapapp\space\thechapter.}%
                         \addcontentsline{toc}{chapter}%
                                   {\protect\numberline{\thechapter}#1}%
                    \else
                      \addcontentsline{toc}{chapter}{#1}%
                    \fi
                    \chaptermark{#1}%
                    \addtocontents{lof}{\protect\addvspace{10\p@}}%
                    \addtocontents{lot}{\protect\addvspace{10\p@}}%
                    \if@twocolumn
                      \@topnewpage[\@makechapterhead{#2}]%
                    \else
                      \@makechapterhead{#2}%
                      \@afterheading
                    \fi}
\def\@makechapterhead#1{%
    \vspace*{50\p@}%
    {%
        \parindent \z@ \raggedright \normalfont
        \ifnum \c@secnumdepth >\m@ne
            \netthesis@chapterfont \@chapapp\space \thechapter
            \par\nobreak
            \vskip 20\p@
        \fi
        \interlinepenalty\@M
        \netthesis@chapterfont #1\par\nobreak
        \vskip 40\p@
    }%
}
\def\@schapter#1{%
                 \@mkboth{#1}{#1}%
                 \if@twocolumn
                   \@topnewpage[\@makeschapterhead{#1}]%
                 \else
                   \@makeschapterhead{#1}%
                   \@afterheading
                 \fi}
\def\@makeschapterhead#1{%
    \vspace*{50\p@}%
    {%
    \parindent \z@ \raggedright \normalfont
    \interlinepenalty\@M
    \netthesis@chapterfont #1\par\nobreak
    \vskip 40\p@
    }%
}
\renewcommand\section{\net@section}
\newcommand\net@section{\@startsection{section}{1}{\z@}%
        {-3.5ex \@plus -1ex \@minus -.2ex}%
        {2.3ex \@plus .2ex}%
        {\raggedright\normalfont\netthesis@sectionfont}%
}
\renewcommand\subsection{\net@subsection}
\newcommand\net@subsection{\@startsection{subsection}{2}{\z@}%
    {-3.25ex\@plus -1ex \@minus -.2ex}%
    {1.5ex \@plus .2ex}%
    {\raggedright\normalfont\netthesis@subsectionfont}%
}
\renewcommand\subsection{\net@subsection}
\newcommand\net@subsubsection{\@startsection{subsubsection}{3}{\z@}%
    {-3.25ex\@plus -1ex \@minus -.2ex}%
    {1.5ex \@plus .2ex}%
    {\normalfont\netthesis@subsubsectionfont}%
}
\renewcommand\paragraph[1]{\net@paragraph{#1%
    \hskip.25\fontdimen2\font
    \protect\rule[.56\fontdimen5\font]{1\fontdimen6\font}{.1\fontdimen5\font}%
    \hskip.25\fontdimen2\font}%
}
\newcommand\net@paragraph{\@startsection{paragraph}{4}{\z@}%
    {3.25ex \@plus 1ex \@minus .2ex}%
    {-0em}%
    {\normalfont\netthesis@paragraphfont}%
}
\renewcommand\subparagraph[1]{\net@subparagraph{#1%
    \hskip.25\fontdimen2\font
    \protect\rule[.56\fontdimen5\font]{1\fontdimen6\font}{.1\fontdimen5\font}%
    \hskip.25\fontdimen2\font}%
}
\newcommand\net@subparagraph{\@startsection{subparagraph}{5}{\parindent}%
    {3.25ex \@plus 1ex \@minus .2ex}%
    {-0em}%
    {\normalfont\netthesis@subparagraphfont}%
}

%----------------------------------------------------------------------
% Figure and table caption styles
%
\setlength\abovecaptionskip{10\p@}
\setlength\belowcaptionskip{0\p@}
\long\def\@makecaption#1#2{%
    \vskip\abovecaptionskip
    \sbox\@tempboxa{\small #1: #2}%
    \ifdim \wd\@tempboxa >\hsize
        \small
        #1: #2\par
    \else
        \global \@minipagefalse
        \hb@xt@\hsize{\hfil\box\@tempboxa\hfil}%
    \fi
    \vskip\belowcaptionskip
}

%----------------------------------------------------------------------
% Table of contents
%
\setcounter{tocdepth}{2}
\renewcommand\tableofcontents{%
    \if@twocolumn
        \@restonecoltrue\onecolumn
    \else
        \@restonecolfalse
    \fi
    \chapter*{\contentsname}%
    \@starttoc{toc}%
    \if@restonecol
        \twocolumn
    \fi
}
\renewcommand*\l@part[2]{%
    \ifnum \c@tocdepth >-2\relax
        \addpenalty{-\@highpenalty}%
        \addvspace{2.25em \@plus\p@}%
        \setlength\@tempdima{3em}%
        \begingroup
            \parindent \z@ \rightskip \@pnumwidth
            \parfillskip -\@pnumwidth
            {\leavevmode\large #1\hfil \hb@xt@\@pnumwidth{\hss #2}}\par
            \nobreak
            \global\@nobreaktrue
            \everypar{\global\@nobreakfalse\everypar{}}%
        \endgroup
    \fi%
}
\renewcommand*\l@chapter[2]{%
    \ifnum \c@tocdepth >\m@ne
        \addpenalty{-\@highpenalty}%
        \vskip 1.0em \@plus\p@
        \setlength\@tempdima{1.5em}%
        \begingroup
            \parindent \z@ \rightskip \@pnumwidth
            \parfillskip -\@pnumwidth
            \leavevmode
            \advance\leftskip\@tempdima
            \hskip -\leftskip
            #1\nobreak\hfil \nobreak\hb@xt@\@pnumwidth{\hss #2}\par
            \penalty\@highpenalty
        \endgroup
    \fi%
}

%----------------------------------------------------------------------
% List of figure and tables
%
\renewcommand\listoffigures{%
    \if@twocolumn
        \@restonecoltrue\onecolumn
    \else
        \@restonecolfalse
    \fi
    \chapter*{\listfigurename}%
    \@starttoc{lof}%
    \if@restonecol
        \twocolumn
    \fi
}
\renewcommand\listoftables{%
    \if@twocolumn
        \@restonecoltrue\onecolumn
    \else
        \@restonecolfalse
    \fi
    \chapter*{\listtablename}%
    \@starttoc{lot}%
    \if@restonecol
        \twocolumn
    \fi
}

%----------------------------------------------------------------------
% Bibliography environment
%
\setcounter{secnumdepth}{3}
\setlength\bibindent{1.5em}
\renewenvironment{thebibliography}[1]{%
    \chapter*{\bibname}%
    \addcontentsline{toc}{chapter}{\bibname}%
    \list{\@biblabel{\@arabic\c@enumiv}}%
         {\settowidth\labelwidth{\@biblabel{#1}}%
          \leftmargin\labelwidth
          \advance\leftmargin\labelsep
          \@openbib@code
          \usecounter{enumiv}%
          \let\p@enumiv\@empty
          \renewcommand\theenumiv{\@arabic\c@enumiv}}%
    \sloppy
    \clubpenalty4000
    \@clubpenalty \clubpenalty
    \widowpenalty4000%
    \sfcode`\.\@m%
}{%
    \def\@noitemerr
     {\@latex@warning{Empty `thebibliography' environment}}%
    \endlist%
}

%----------------------------------------------------------------------
% Index environment %TODO
%
\renewenvironment{theindex}{%
    \if@twocolumn
        \@restonecolfalse
    \else
        \@restonecoltrue
    \fi
    \twocolumn[\@makeschapterhead{\indexname}]%
    \@mkboth{\indexname}{\indexname}%
    \addcontentsline{toc}{chapter}{\indexname}%
    \thispagestyle{reportchapter}\parindent\z@
    \parskip\z@ \@plus .3\p@\relax
    \columnseprule \z@
    \columnsep 35\p@
    \let\item\@idxitem
}{%
    \if@restonecol
        \onecolumn
    \else
        \clearpage
    \fi
}

%----------------------------------------------------------------------
% Title page
%
\newcommand\@committeechair{\makebox[7cm]{\dotfill}}
\newcommand\@committeeexamineri{\makebox[7cm]{\dotfill}}
\newcommand\@committeeexaminerii{\makebox[7cm]{\dotfill}}
\newcommand\@committeeexamineriii{\makebox[7cm]{\dotfill}}
\newcommand\committeechair[1]{%
    \isequal{#1}{\@empty}\ifequal\relax\else
        \renewcommand\@committeechair{#1}%
    \fi
}
\newcommand\committeeexaminers[3]{%
    \isequal{#1}{\@empty}\ifequal\relax\else
        \renewcommand\@committeeexamineri{#1}%
    \fi%
    \isequal{#2}{\@empty}\ifequal\relax\else
        \renewcommand\@committeeexaminerii{#2}%
    \fi%
    \isequal{#3}{\@empty}\ifequal\relax\else
        \renewcommand\@committeeexamineriii{#3}%
    \fi%
}
\newcommand\@submitteddate{\makebox[2.5cm]{\dotfill}}
\newcommand\@accepteddate{\makebox[2.5cm]{\dotfill}}
\newcommand\submitteddate[1]{%
    \isequal{#1}{\@empty}\ifequal\relax\else
        \renewcommand\@submitteddate{#1}%
    \fi
}
\newcommand\accepteddate[1]{%
    \isequal{#1}{\@empty}\ifequal\relax\else
        \renewcommand\@accepteddate{#1}%
    \fi
}
\renewenvironment{titlepage}{%
    \if@twocolumn
        \@restonecoltrue\onecolumn
    \else
        \@restonecolfalse\newpage
    \fi
    \thispagestyle{reporttitle}%
    \setcounter{page}\@ne
}{%
    \if@restonecol
        \twocolumn
    \else
        \newpage
    \fi
    \if@twoside
    \else
        \setcounter{page}\@ne
    \fi
}
\renewcommand\maketitle{%
    \begin{titlepage}%
        \let\footnotesize\small
        \let\footnoterule\relax
        \let \footnote \thanks
        %\null\vfil
        \netthesis@titlepage
        %\vfil\null
    \end{titlepage}%
    \setcounter{footnote}{0}%
    \global\let\thanks\relax
    \global\let\maketitle\relax
    \global\let\@thanks\@empty
    \global\let\@author\@empty
    \global\let\@date\@empty
    \global\let\@title\@empty
    \global\let\title\relax
    \global\let\author\relax
    \global\let\date\relax
    \global\let\and\relax
    \global\let\@committeechair
    \global\let\@committeeexamineri\@empty
    \global\let\@committeeexaminerii\@empty
    \global\let\@committeeexamineriii\@empty
    \global\let\committeechair\relax
    \global\let\committeeexaminers\relax
    \global\let\@submitteddate\@empty
    \global\let\@accepteddate\@empty
    \global\let\submitteddate\relax
    \global\let\accepteddate\relax
}

%----------------------------------------------------------------------
% Document specific title pages
%
\AtBeginDocument{\providecommand\microtypesetup{\@gobble}}
\newcommand\netthesis@plaintitle{%
    \begingroup
    \microtypesetup{expansion=false}%
    \vskip 60\p@
    \begin{center}%
        {\LARGE \@title \par}%
        \vskip 3em%
        {\large
            \lineskip .75em%
            \begin{tabular}[t]{c}%
                \@author
            \end{tabular}\par
        }%
        \vskip 1.5em%
        {\large \@date \par}%
    \end{center}\par
    \endgroup
    \@thanks
}

\newcommand\netthesis@thesistitle{%
	\begingroup%
	\thispagestyle{empty}%
	\microtypesetup{expansion=false}%
	\TUMlogo{height=3em,color=TUMBlack,shape=outline}%
	\hfill%
	\INlogo{height=3em,color=TUMBlack}

	\vskip1mm
	
	\hrule

	\vskip30mm

	\begin{center}
		{\huge \textsc{\TUMnamegerman}}\\
		\vskip2mm
		\ifnet@german
			{\Large \textsc{\INnamegerman}}\\
			\vskip20mm
			{\Large \textsc{\thesisdescription}}\\
			\vskip20mm
			{\huge\bfseries \@titlegerman}\\
		\else
			{\Large \textsc{\INnameenglish}}\\
			\vskip20mm
			{\Large \textsc{\thesisdescription}}\\
			\vskip20mm
			{\huge\bfseries \@titleenglish}\\
		\fi
			
		\vskip20mm%
		{\Large  \@author}\\
	\end{center}
	
	\vfill
	
	\hrule

	\vskip1mm
	
	\begin{spacing}{0.8}
		\vphantom{
        	\begin{minipage}[b]{.7\textwidth}
			\footnotesize
        	        	Informatik VIII\\
        	        	\NETnameenglish
        	\end{minipage}%
        	\hfill
        	\begin{minipage}[b]{.25\textwidth}
        		\hfill
        		\NETlogo{height=3em,color=TUMBlack}
        	\end{minipage}
	}
	\end{spacing}

	\clearpage%
	\endgroup%

	\cleardoublepage

	\begingroup%
	\thispagestyle{empty}%
	\setcounter{page}{1}%
	\microtypesetup{expansion=false}%
	\TUMlogo{height=3em,color=TUMBlack,shape=outline}%
	\hfill%
	\INlogo{height=3em,color=TUMBlack}

	\vskip1mm

	\hrule

	\vskip30mm

	\begin{center}
		{\huge \textsc{\TUMnamegerman}}\\
		\vskip2mm
		\ifnet@german
			{\Large \textsc{\INnamegerman}}\\
			\vskip20mm
			{\Large \textsc{\thesisdescription}}\\
			\vskip20mm%
			{\Large \@titlegerman}\\
			\vskip5mm
			{\Large \@titleenglish}\\
		\else
			{\Large \textsc{\INnameenglish}}\\
			\vskip20mm
			{\Large \textsc{\thesisdescription}}\\
			\vskip20mm%
			{\Large \@titleenglish}\\
			\vskip5mm
			{\Large \@titlegerman}\\
		\fi
		\vskip20mm%
		\begin{tabular}{ll}
			{\em \authorstring}	& \@author\\
			{\em \supervisorstring} & \@supervisor\\
			{\em \advisorstring}	& \@advisor\\
			{\em \datestring}	& \@submitteddate
		\end{tabular}
	\end{center}
		
	\vfill
	
	\hrule

	\vskip1mm
	
	\begin{spacing}{0.8}
        	\begin{minipage}[b]{.7\textwidth}
			\footnotesize
                	Informatik VIII\\
			\ifnet@german
				\NETnamegerman
			\else
                		\NETnameenglish
			\fi
        	\end{minipage}%
        	\hfill
        	\begin{minipage}[b]{.25\textwidth}
        		\hfill
        		\NETlogo{height=3em,color=TUMBlack}
        	\end{minipage}
	\end{spacing}

	\clearpage
	\endgroup
	

	\cleardoublepage
	
	\isequal{\netthesis@document}{idp}
	\ifequal
	\else
	\begingroup
	\thispagestyle{empty}

	\mbox{}
	\vfill
	\hrule

	\vskip2mm
	\ifnet@german
	Ich ver\-si\-che\-re, dass ich die vor\-lie\-gen\-de Ar\-beit
	selbst\-st\"an\-dig ver\-fasst und nur die an\-ge\-ge\-ben\-en
	Quel\-len und Hilfs\-mit\-tel ver\-wen\-det ha\-be.
	\else
	I con\-firm that this thesis is my own work and I have do\-cu\-men\-ted
	all sour\-ces and ma\-te\-ri\-al used. 
	\fi

	\newlength\netthesis@sigline
	\setlength\netthesis@sigline{6cm}

	\vskip4em
	Garching b. M\"unchen, \@submitteddate%
	\hfill%
	\rule[-.4em]{\the\netthesis@sigline}{0.25mm}

	\ifnet@german
	\setlength{\netthesis@sigline}{\netthesis@sigline-\widthof{Unterschrift}}
	\hfill Unterschrift\hspace{\the\netthesis@sigline}
	\else
	\setlength{\netthesis@sigline}{\netthesis@sigline-\widthof{Signature}}
	\hfill Signature\hspace{\the\netthesis@sigline}
	\fi

	\vskip2cm
	\clearpage
	\endgroup
	
	\cleardoublepage
	\fi
}
\newcommand\netthesis@dissertationtitle{%
    \begingroup
    \microtypesetup{expansion=false}%
    \begin{center}%
        {\LARGE\MakeUppercase\TUMname}\\
        {\Large\MSVnamegerman}\par
        \vfill
        \vskip 70\p@
        {\LARGE\bfseries \@title}\par
        \vskip 40\p@
        {\Large \@author}
    \end{center}
    \vskip 60\p@
    \vfill
    \noindent\large\sloppy
    Voll\-st\"an\-diger Ab\-druck der von der Fa\-kul\-t\"at f\"ur
    Elek\-tro\-tech\-nik und In\-for\-ma\-ti\-ons\-tech\-nik der
    Tech\-nisch\-en Uni\-ver\-si\-t\"at M\"unchen zur Er\-lan\-gung des
    aka\-de\-misch\-en Gra\-des eines
    \begin{center}
        Doktor-Ingenieurs
    \end{center}
    ge\-neh\-mig\-ten Dis\-ser\-ta\-ti\-on.\par
    \vskip 30\p@
    \hspace*{40\p@}%
    \begin{tabular}{rl}
        Vorsitzender:   &  \@committeechair\\
        \multicolumn{2}{l}{Pr\"ufer der Dissertation:} \\
        1. & \@committeeexamineri\\
        2. & \@committeeexaminerii\\
           & \@committeeexamineriii
    \end{tabular}\par
    \vskip 30\p@
    \noindent\large
    Die Dis\-ser\-ta\-ti\-on wur\-de am \@submitteddate\ bei der
    Tech\-nisch\-en Uni\-ver\-si\-t\"at M\"unchen ein\-ge\-rei\-cht und
    durch die Fa\-kul\-t\"at f\"ur Elek\-tro\-tech\-nik und
    In\-for\-ma\-ti\-ons\-tech\-nik am \@accepteddate\
    an\-ge\-nom\-men.\par\normalsize\fussy
    \endgroup
    \@thanks
}


\endinput

