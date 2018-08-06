%
% nettutorial.cls
%
%

%----------------------------------------------------------------------
% Identify class
%
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{nettutorial}%
    [2015/10/07 v0.01.0 %
    nettutorial.cls NET tutorial class %
    based on msvreport.cls]

%----------------------------------------------------------------------
% Class options
%
\RequirePackage{kvoptions}%
\SetupKeyvalOptions{family=nettutorial,prefix=nettutorial@}%
% netcommon.sty
\DeclareBoolOption{german}
\DeclareVoidOption{ngerman}{%
	\nettutorial@germantrue%
	\PassOptionsToPackage{netcommon}{ngerman}}%
\DeclareVoidOption{german}{%
	\nettutorial@germantrue%
	\PassOptionsToPackage{netcommon}{german}}%
% nettutorial.cls
% Process options
\ProcessKeyvalOptions*\relax

%----------------------------------------------------------------------
% Load base class report and required packages
%
\LoadClassWithOptions{scrartcl}
\RequirePackage{xparse}
\RequirePackage{geometry}
\RequirePackage{netcommon}
\RequirePackage{amsbsy}
\RequirePackage{amsmath}
\RequirePackage{amssymb}
\RequirePackage{amsthm}
\RequirePackage{setspace}
\RequirePackage{adjustbox}
\RequirePackage{ifthen}

%----------------------------------------------------------------------
% Fonts
%
\RequirePackage[scaled]{helvet}
\RequirePackage{inconsolata}
\renewcommand\familydefault{\sfdefault}
\RequirePackage{sfmath}% Takes care of math mode in general
\RequirePackage[Euler]{upgreek}% That + renews give meaningful greek letters
% helvet font.

% Make helvet the default for all
\renewcommand\rmdefault{ptm}%
\renewcommand\sfdefault{phv}%
\renewcommand\ttdefault{pcr}%

% Kill that all if you wanna use timesmath
\renewcommand{\alpha}{\upalpha}
\renewcommand{\beta}{\upbeta}
\renewcommand{\gamma}{\upgamma}
\renewcommand{\delta}{\updelta}
\renewcommand{\epsilon}{\upepsilon}
\renewcommand{\zeta}{\upzeta}
\renewcommand{\eta}{\upeta}
\renewcommand{\theta}{\uptheta}
\renewcommand{\kappa}{\upkappa}
\renewcommand{\lambda}{\uplambda}
\renewcommand{\mu}{\upmu}
\renewcommand{\nu}{\upnu}
\renewcommand{\xi}{\upxi}
\renewcommand{\pi}{\uppi}
\renewcommand{\rho}{\uprho}
\renewcommand{\sigma}{\upsigma}
\renewcommand{\tau}{\uptau}
\renewcommand{\phi}{\upphi}
\renewcommand{\chi}{\upchi}
\renewcommand{\psi}{\uppsi}
\renewcommand{\omega}{\upomega}
\renewcommand{\Gamma}{\Upgamma}
\renewcommand{\Delta}{\Updelta}
\renewcommand{\Theta}{\Uptheta}
\renewcommand{\Lambda}{\Uplambda}
\renewcommand{\Xi}{\Upxi}
\renewcommand{\Pi}{\Uppi}
\renewcommand{\Phi}{\Upphi}
\renewcommand{\Psi}{\Uppsi}
\renewcommand{\Omega}{\Upomega}

%----------------------------------------------------------------------
% Language stuff
%
\def\@problemlabel{Problem}
\def\@tutoriallabel{Tutorial}
\def\@solutionlabel{Solution}
\def\@notetext{\textbf{Note:} Subproblems marked by * can be solved without
results of preceeding subproblems.}

\ifnettutorial@german
	\def\@problemlabel{Aufgabe}
	\def\@tutoriallabel{\"Ubungsblatt}
	\def\@solutionlabel{L\"osung}
	\def\@notetext{\textbf{Hinweis:} Mit * gekennzeichneite Teilaufgaben sind
	ohne Kenntnis der Ergebnisse vorhergehender Teilaufgaben l\"osbar.}
\fi


%----------------------------------------------------------------------
% solutionswitch
%
\RequirePackage{solutionswitch}
\ifsolution
\usepackage{draftwatermark}
\SetWatermarkText{\@solutionlabel}
\SetWatermarkColor{blue!20}
\SetWatermarkFontSize{2.5cm}
\fi

%----------------------------------------------------------------------
% Document commands
%
\def\@assistantA{}
\def\@assistantB{}
\def\@assistantC{}
\def\@assistantD{}
\def\@assistantE{}
\DeclareDocumentCommand{\persons}{m o o o o}{%
\gdef\@assistantA{#1}
\IfNoValueF{#2}{\gdef\@assistantB{#2}}
\IfNoValueF{#3}{\gdef\@assistantC{#3}}
\IfNoValueF{#4}{\gdef\@assistantD{#4}}
\IfNoValueF{#5}{\gdef\@assistantE{#5}}
}

\def\@chairname{}
\DeclareDocumentCommand{\chair}{m}{\gdef\@chairname{#1}}

\def\@tutorialnumber{}
\def\@tutorialdate{}
\DeclareDocumentCommand{\tutorial}{o m}{%
\IfNoValueF{#1}{\gdef\@tutorialdate{#1}}
\gdef\@tutorialnumber{#2}%
}

\def\@lecturename{}
\DeclareDocumentCommand{\lecture}{o m}{%
\IfNoValueF{#1}{\gdef\@term{#1}}
\gdef\@lecturename{#2}
}

\renewcommand*{\maketitle}{%
\adjustbox{valign=t}{\begin{minipage}[t]{.75\textwidth}
\begin{tabular}{|l|}%
\TUMname\\
\ifx\@chairname\empty\else\@chairname\fi
\ifx\@assistantA\empty\else\\\@assistantA\fi
\ifx\@assistantB\empty\else\\\@assistantB\fi
\ifx\@assistantC\empty\else\\\@assistantC\fi
\ifx\@assistantD\empty\else\\\@assistantD\fi
\ifx\@assistantE\empty\else\\\@assistantE\fi
\end{tabular}
\end{minipage}}%
\adjustbox{valign=t}{\begin{minipage}[t]{.25\textwidth}
\hfill\TUMlogo{height=1.25cm}
\end{minipage}}
\vskip2em
\begin{center}
	\large
	\textbf{\@lecturename%
	\ifx\@term\empty\else\ \textbf{(\@term)}\fi}\\[.5em]
	\ifx\@tutorialnumber\empty\else\ \textbf{\@tutoriallabel\ \@tutorialnumber}\fi
	\ifx\@tutorialdate\empty\else\ \textbf{(\@tutorialdate)}\fi
\end{center}
\vskip2em
}

\newcommand{\note}{
\@notetext
}

\newcounter{ProblemCounter}
\newcounter{SubProblemCounter}[ProblemCounter]

\DeclareDocumentCommand{\problem}{m o}{%
	\vskip2em
	\stepcounter{ProblemCounter}
	\Large\textbf{\@problemlabel\ \arabic{ProblemCounter}} \ %
	\textbf{\normalsize #1}\normalsize%
	\IfNoValueF{#2}{\hfill[\ifthenelse{\equal{#2}{1}}{#2 credit}{#2 credits}]}%
	\vskip.4em
}

\DeclareDocumentCommand{\subproblem}{s}{%
	\vskip1em
	\stepcounter{SubProblemCounter}
	\alph{SubProblemCounter})%
	\ifx#1\BooleanTrue*\fi\ %
}

\DeclareDocumentCommand{\solution}{m o}{%
	\color{blue}
	\ifsolution
	#1
	\else
	\IfNoValueF{#2}
	\fi
	\normalcolor
}

\setlength\parindent{0pt}


%----------------------------------------------------------------------
% Page geometry
%
\newgeometry{
	top=2.5cm,
	bottom=2.5cm,
	left=2cm,
	right=2cm
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

\endinput
