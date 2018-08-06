%
% tumthesis.cls
%
%

%----------------------------------------------------------------------
% Identify class
%
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{tumthesis}%
    [2014/11/26 v0.01.0 %
    tumthesis.cls NET thesis class %
    based on msvreport.cls]

%----------------------------------------------------------------------
% Class options
%
\RequirePackage[english,ngerman]{babel}
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{report}}%
\DeclareOption*{\PassOptionsToPackage{\CurrentOption}{tumlang}}%
\DeclareOption{dissertation}{%
    \def\tumthesis@document{dissertation}
    \def\tumthesis@titlepage{\tumthesis@dissertationtitle}
}
\DeclareOption{bachelor}{%
    \def\tumthesis@document{bachelor}
    \def\tumthesis@titlepage{\tumthesis@thesistitle}
    \addto\captionsenglish{%
        \def\thethesistype{Bachelor's Thesis}
    }
    \addto\captionsngerman{%
        \def\thethesistype{Bachelor's Thesis}
    }
}
\DeclareOption{master}{%
    \def\tumthesis@document{master}
    \def\tumthesis@titlepage{\tumthesis@thesistitle}
    \addto\captionsenglish{%
        \def\thethesistype{Master's Thesis}
    }
    \addto\captionsngerman{%
        \def\thethesistype{Master's Thesis}
    }
}
\DeclareOption{idp}{%
    \def\tumthesis@document{idp}
    \def\tumthesis@titlepage{\tumthesis@thesistitle}
    \addto\captionsenglish{%
        \def\thesisdescription{Interdisciplinary Project in Electrical Engineering}
    }
    \addto\captionsngerman{%
        \def\thesisdescription{Interdisziplin{\"a}res Projekt in Elektrotechnik}
    }
}
% Dr.-Ing. instead of Dr. rer. nat.
\newif\if@dring\@dringfalse
\DeclareOption{dring}{
  \@dringtrue
}
% Process options
\ProcessOptions\relax

%----------------------------------------------------------------------
% Load base class report and required packages
%
\LoadClassWithOptions{report}
\RequirePackage{tumlang}
\RequirePackage{tumcolor}
\RequirePackage{tumcontact}
\RequirePackage{geometry}
\RequirePackage{setspace}
\RequirePackage{parskip}
\RequirePackage[pagestyles,clearempty]{titlesec}
\RequirePackage{pfnote}        % per-page footnotes
\RequirePackage{iflang}
\RequirePackage{tumcmd}

%----------------------------------------------------------------------
% Page geometry
%
\geometry{%
    a4paper,
    top=.08333\paperheight,
    bottom=.16667\paperheight,
    inner=.08333\paperwidth+10mm,
    outer=.16667\paperwidth,
    includehead=true,
    footskip=2cm,
    footskip=.08333\paperheight,
}
\linespread{1.18}
\clubpenalty10000
\widowpenalty10000
\raggedbottom

%----------------------------------------------------------------------
% pagestyles
%
\setmarks{chapter}{section}
\gdef\ttl@savemark{} % needed for TOC
\newpagestyle{thesis}{%
    \sethead[%
        \ifnum0<\value{chapter}%
            \scshape{\chaptername\ \thechapter:\quad\chaptertitle}
        \fi
    ][][]{}{}{%
        \ifnum0<\value{chapter}%
            \scshape{\thesection\quad\sectiontitle}
        \fi
    }
    \setfoot[\thepage][][]{}{}{\thepage}
}
\newpagestyle{thesischapter}{%
    \sethead[][][]{}{}{}
    \setfoot[\thepage][][]{}{}{\thepage}
}
\newpagestyle{thesistoc}{%
    \sethead[][][]{}{}{}
    \setfoot[\thepage][][\thepage]{}{}{}
}
\newpagestyle{thesisbibliography}{%
    \sethead[\scshape\chaptertitle][][]{}{}{\scshape\chaptertitle}
    \setfoot[\thepage][][]{}{}{\thepage}
}
\renewpagestyle{plain}{%
    \sethead[][][]{}{}{}
    \setfoot[\thepage][][\thepage]{}{}{}
}
\setlength{\footnotesep}{0.5cm}
\setlength{\skip\footins}{1cm}
\pagestyle{thesis}

%----------------------------------------------------------------------
% Do document specific things
%
\def\thetitle{}
\newcommand{\titleenglish}[1]{%
    \addto\captionsenglish{%
        \def\thetitle{#1}%
    }%
}
\newcommand{\titlegerman}[1]{%
    \addto\captionsngerman{%
        \def\thetitle{#1}%
    }%
}
\def\thelocation{}
\newcommand{\location}[1]{%
    \def\thelocation{#1}
}
\def\theadvisor{}
\newcommand{\advisor}[1]{%
    \def\theadvisor{#1}%
}
\def\thesupervisor{}
\newcommand{\supervisor}[1]{%
    \def\thesupervisor{#1}%
}
\def\thecourseofstudy{}
\newcommand{\courseofstudy}[1]{%
    \def\thecourseofstudy{#1}
}

\addto\captionsenglish{%
    \def\authorlabel{Author}
    \def\supervisorlabel{Supervisor}
    \def\advisorlabel{Advisor}
    \def\datelabel{Date}
    \def\abstractname{Abstract}
    \def\locationlabel{Location}
    \def\signaturelabel{Signature}
    \def\assurance{I confirm that this \thethesistype{} is my own work and I
    have documented all sources and material used.}
}
\addto\captionsngerman{%
    \def\authorlabel{Bearbeiter}
    \def\supervisorlabel{Aufgabensteller}
    \def\advisorlabel{Betreuer}
    \def\datelabel{Datum}
    \def\abstractname{Zusammenfassung}
    \def\locationlabel{Ort}
    \def\signaturelabel{Unterschrift}
    \def\assurance{Ich versichere, dass ich diese \thethesistype{}
    selbst\"andig verfasst und nur die angegebenen Quellen und Hilfsmittel
    verwendet habe.}
}



%----------------------------------------------------------------------
% Chapter and Section styles
%
\titleformat{\chapter}[display]{%
        \normalfont\scshape\huge%
    }{%
        \hfill\Huge\chaptername\ \thechapter}{1em}{}
\titleformat{\section}[hang]{\normalfont\scshape\Large}{\thesection}{1em}{}
\titleformat{\subsection}[hang]{\normalfont\scshape\large}{\thesubsection}{1em}{}
\titleformat{\subsubsection}[hang]{\normalfont\scshape\normalsize}{\thesubsubsection}{1em}{}
\titleformat{\paragraph}[runin]{\normalfont\slshape}{\theparagraph}{0pt}{}[:]

%\titlespacing{\chapter}{0pt}{3.5ex plus 1ex minus .2ex}{2.3ex plus .2ex}
\titlespacing{\section}{0pt}{3.5ex plus 1ex minus .2ex}{2.3ex plus .2ex}
\titlespacing{\subsection}{0pt}{3.25ex plus 1ex minus .2ex}{.5ex plus .2ex}
\titlespacing{\subsubsection}{0pt}{3.25ex plus 1ex minus .2ex}{0ex plus .2ex}
%\renewcommand\paragraph[1]{%
%    {\textit{#1}\,---}%
%}

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
    \cleardoublepage
    \setcounter{page}{1}
    \pagenumbering{Roman}
    \chapter*{\scshape\contentsname}%
    \@starttoc{toc}%
    \clearpage%
    \thispagestyle{empty}%
    \cleardoublepage%
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
            \bfseries{#1\nobreak\hfil \nobreak\hb@xt@\@pnumwidth{\hss #2}\par}
            \penalty\@highpenalty
        \endgroup
    \fi%
}

%----------------------------------------------------------------------
% List of figure and tables
%
\renewcommand\listoffigures{%
    \cleardoublepage
    \chapter*{\scshape\listfigurename}%
    \@starttoc{lof}%
    \clearpage
    \thispagestyle{empty}
}
\renewcommand\listoftables{%
    \cleardoublepage
    \chapter*{\scshape\listtablename}%
    \@starttoc{lot}%
    \clearpage
    \thispagestyle{empty}
}

\newcommand{\startcontent}{%
    \cleardoublepage
    \pagenumbering{arabic}
    \setcounter{page}{1}
    \allowdisplaybreaks
}

%----------------------------------------------------------------------
% thanks environment
%
\newenvironment{preface}{%
    \cleardoublepage%
    \chapter*{\scshape Preface}%
}{%
    \clearpage%
}

\renewenvironment{thanks}{%
    \clearpage%
    \vspace*{\fill}%
}{%
    \cleardoublepage%
}

\renewenvironment{abstract}{%
    \cleardoublepage%
    \begin{center}%
        \scshape\large\abstractname%
    \end{center}%
}{%
    \clearpage%
}

%----------------------------------------------------------------------
% Index environment %TODO
%
\renewenvironment{theindex}{%
    \@mkboth{\indexname}{\indexname}%
    \addcontentsline{toc}{chapter}{\indexname}%
    \thispagestyle{thesischapter}\parindent\z@
    \parskip\z@ \@plus .3\p@\relax
    \columnseprule \z@
    \columnsep 35\p@
    \let\item\@idxitem
}{%
    \clearpage
}

%----------------------------------------------------------------------
% Title page
%
\def\thedate{\makebox[4cm]{\dotfill}}
\def\theacceptancedate{\makebox[4cm]{\dotfill}}
\renewcommand{\date}[2][]{%
    \ifx\@empty#1\@empty\relax\else%
        \def\theacceptancedate{#1}%
    \fi%
    \def\thedate{#2}%
}
\renewenvironment{titlepage}{%
    \thispagestyle{empty}%
    \setcounter{page}\@ne
}{%
    \cleardoublepage
    \setcounter{page}\@ne
}
\def\maketitle{%
    \@ifstar%
    {\tumthesis@titlepage{1}}%
    {\tumthesis@titlepage{0}}%
}

%----------------------------------------------------------------------
% Document specific title pages
%
\AtBeginDocument{\providecommand\microtypesetup{\@gobble}}
\newcommand\tumthesis@plaintitle{%
    \begingroup
    \microtypesetup{expansion=false}%
    \vskip 60\p@
    \begin{center}%
        {\LARGE \thetitle \par}%
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

\newcommand\tumthesis@dissertationtitle[1]{%
    \begin{titlepage}
    \begingroup
    \microtypesetup{expansion=false}%
    \begin{center}%
        \selectlanguage{ngerman}
        {\huge\scshape\TUMname}\par
        {\Large\scshape\chairname}\par
        {\Large\scshape\departmentname}\par
        \selectlanguage{english}
        \vspace{3\baselineskip}
        {\Large\thetitle}\par
        \vspace{\baselineskip}
        {\@author}
    \end{center}
    \vspace{3\baselineskip}
    \selectlanguage{ngerman}
    {\noindent\normalsize\sloppy
    Voll\-st\"an\-diger Ab\-druck der von der \departmentname\ der
    Tech\-nisch\-en Uni\-ver\-si\-t\"at M\"unchen zur Er\-lan\-gung des
    aka\-de\-misch\-en Gra\-des eines
    \begin{center}
        \if@dring
            {\scshape Doktor-Ingenieurs}%
        \else
            {\scshape Doktors der Naturwissenschaften}%
        \fi
    \end{center}%
    ge\-neh\-mig\-ten Dis\-ser\-ta\-ti\-on.

    \ifnum#1=1\color{white}\else\fi%
    \renewcommand{\arraystretch}{1.18}\selectfont
    \begin{tabular}{rl}
        Vorsitzender: & \makebox[7cm]{\dotfill}\\
        \multicolumn{2}{l}{Pr\"ufer der Dissertation:} \\
        1. & \thesupervisor\\
        2. & \theadvisor
    \end{tabular}\par

    \vspace{2\baselineskip}
    \renewcommand{\arraystretch}{1.9}\selectfont
    \noindent{%
    \normalsize
    \linespread{1.9}\selectfont
    Die Dis\-ser\-ta\-ti\-on wur\-de am \thedate\ bei der
    Tech\-nisch\-en Uni\-ver\-si\-t\"at M\"unchen ein\-ge\-reicht und
    durch die \departmentname\ am \theacceptancedate\
    an\-ge\-nom\-men.\par\normalsize\fussy
    }}
    \endgroup
    \@thanks
    \end{titlepage}
}

\newcommand\tumthesis@thesistitle[1]{%
    \begin{titlepage}
        \begingroup
            \fontfamily{phv}\selectfont
            \TUMheader{1cm}
            \vspace*{6\baselineskip}
            \begin{center}%
                {\huge\scshape\TUMname\par}
                {\Large\scshape\departmentname\par}
                \vspace{4\baselineskip}
                {\Large\scshape\thethesistype{} in \thecourseofstudy\par}
                \vspace{4\baselineskip}
                {\Large\bfseries{\thetitle}\par}
                \vspace{4\baselineskip}
                {\Large\@author\par}
            \end{center}
            \vspace{4\baselineskip}
            \noindent\normalsize\sloppy
        \endgroup
    \end{titlepage}

    \cleardoublepage

    \begin{titlepage}
        \begingroup
            \microtypesetup{expansion=false}%
            \vspace*{\fill}
            \begin{center}%
                {\huge\scshape\TUMname\par}
                {\LARGE\scshape\departmentname\par}
                \vspace{4\baselineskip}
                {\Large\thethesistype{} in \thecourseofstudy\par}
                \vspace{4\baselineskip}
                {\LARGE\bfseries{\thetitle}\par}
                {
                    \IfLanguageName{english}{%
                        \selectlanguage{ngerman}
                        {\LARGE\bfseries{\thetitle}\par}
                    }{%
                        \selectlanguage{english}
                        {\LARGE\bfseries{\thetitle}\par}
                    }
                }
                \vspace{4\baselineskip}

                \parbox{0pt}{%
                    \begin{tabbing}
                        \hspace{3cm} \= \hphantom{k}\kill
                        \authorlabel: \> \@author\\
                        \supervisorlabel: \> \thesupervisor\\
                        \advisorlabel: \> \theassistants[1]\\
                        \ifnum\theassistantscount<2\relax\else
                        \> \begin{varwidth}{.5\textwidth}
                            \foreach \x in {2,...,\theassistantscount} {
                                \theassistants[\x]%
                                \ifnum\x<\theassistantscount\relax\\\else\fi
                            }%
                        \end{varwidth}\\[1ex]
                        \fi
                        \datelabel: \> \thedate
                    \end{tabbing}
                }
            \end{center}
            \noindent\normalsize\sloppy
            \vfill
        \endgroup
    \end{titlepage}

    \cleardoublepage

    \begin{titlepage}
        \vspace*{\fill}
        \begingroup
            \assurance\\[2\baselineskip]
            \thelocation, \thedate\\[-2.5ex]
            \begin{minipage}[t]{.45\textwidth}%
                \rule{\textwidth}{.5pt}\\[-1ex]
                {\small\hspace*{1ex}\locationlabel, \datelabel}
            \end{minipage}%
            \hfill%
            \begin{minipage}[t]{.45\textwidth}%
                \rule{\textwidth}{.5pt}\\[-1ex]
                {\small\hspace*{1ex}\signaturelabel}
            \end{minipage}%
        \endgroup
    \end{titlepage}
}

\endinput

