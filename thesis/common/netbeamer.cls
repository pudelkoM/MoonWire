%
% netbeamer.cls
%
% This class defines the official NET beamer presentation style
%

%----------------------------------------------------------------------
% Identify class
%
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{netbeamer}%
    [2015/02/26 v1.1 %
    netbeamer.cls NET presentation class based on beamer.cls]

%----------------------------------------------------------------------
% File encoding utf8x
%
\RequirePackage{ucs}
\RequirePackage[utf8x]{inputenc}
\RequirePackage{netcommon}

%----------------------------------------------------------------------
% Class options
%
\RequirePackage{kvoptions}%
\SetupKeyvalOptions{family=netbeamer,prefix=netbeamer@}%
% netcommon.sty
\DeclareVoidOption{ngerman}{\PassOptionsToPackage{ngerman}{netcommon}}%
\DeclareVoidOption{german}{\PassOptionsToPackage{german}{netcommon}}%
\DeclareStringOption[1]{scalehelv}[0.92]%
\DeclareBoolOption[false]{timesmath}%
\DeclareComplementaryOption{cmrmath}{timesmath}%
\DeclareBoolOption[false]{cmyk}%
\DeclareComplementaryOption{rgb}{cmyk}%
\DeclareVoidOption{print}{\netbeamer@cmyktrue}%
% netbeamer.cls
\DeclareBoolOption{smooth}
\DeclareBoolOption{bold}
\DeclareBoolOption{colorblock}
\DeclareBoolOption{blocktitle}
\DeclareBoolOption{lecture}
\DeclareStringOption[1]{logo}%
\DeclareStringOption[TUMDarkerBlue]{basecolor}
% Default option -- this seems not to work anyway!
%\DeclareDefaultOption{\PassOptionsToClass{\CurrentOption}{beamer}}%
\ProcessKeyvalOptions*\relax
% pass non-void options to packages
\PassOptionsToPackage{scalehelv=\netbeamer@scalehelv}{netcommon}
\ifnetbeamer@timesmath
    \PassOptionsToPackage{timesmath=true}{netcommon}
\else
    \PassOptionsToPackage{timesmath=false}{netcommon}
\fi

%----------------------------------------------------------------------
% Font settings
%
\RequirePackage{helvet}% Touch here if you want the TUM font
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
% Commands specific to the beamer template
%
\newcommand\@chair{}
\newcommand\chair[1]{%
        \isequal{#1}{\@empty}\ifequal\relax\else
    \renewcommand\@chair{#1}
    \fi
}
\newcommand\@department{}
\newcommand\department[1]{%
        \isequal{#1}{\@empty}\ifequal\relax\else
    \renewcommand\@department{#1}
    \fi
}
\newcommand\@moduletitle{}
\newcommand\moduletitle[1]{%
        \isequal{#1}{\@empty}\ifequal\relax\else
    \renewcommand\@moduletitle{#1}
    \fi
}
\newcommand\@moduleshorttitle{}
\newcommand\moduleshorttitle[1]{%
        \isequal{#1}{\@empty}\ifequal\relax\else
    \renewcommand\@moduleshorttitle{#1}
    \fi
}
\newcommand\@modulenumber{}
\newcommand\modulenumber[1]{%
        \isequal{#1}{\@empty}\ifequal\relax\else
    \renewcommand\@modulenumber{#1}
    \fi
}
\newcommand\@lecturetitle{}
\newcommand\lecturetitle[1]{%
  \isequal{#1}{\@empty}\ifequal\relax\else
  \renewcommand\@lecturetitle{#1}
  \fi
}
\newcommand\@lecturer{}
\newcommand\lecturer[1]{%
        \isequal{#1}{\@empty}\ifequal\relax\else
    \renewcommand\@lecturer{#1}
    \fi
}
\newcommand\@term{}
\newcommand\term[1]{%
        \isequal{#1}{\@empty}\ifequal\relax\else
    \renewcommand\@term{#1}
    \fi
}
\newcommand\@logo{}
\isequal{\netbeamer@logo}{\@empty}\ifequal
	\renewcommand\@logo[1]{\NETlogo{#1}}
\else
	\isequal{\netbeamer@logo}{MSV}\ifequal
		\renewcommand\@logo[1]{\MSVlogo{#1}}
	\fi
	\isequal{\netbeamer@logo}{NET}\ifequal
		\renewcommand\@logo[1]{\NETlogo{#1}}
	\fi
	\isequal{\netbeamer@logo}{OS}\ifequal
		\renewcommand\@logo[1]{\OSlogo{#1}}
	\fi
\fi

%----------------------------------------------------------------------
% Load base class beamer and required packages
%
\LoadClassWithOptions{beamer}
\RequirePackage{netcommon}
\RequirePackage{amsbsy}
\RequirePackage{amsmath}
\RequirePackage{amssymb}
\RequirePackage{graphics}

%----------------------------------------------------------------------
% Configure beamer templates
%
\beamertemplatenavigationsymbolsempty
\usetheme{default}
\usefonttheme{professionalfonts}
\setbeamerfont{footnote}{size=\tiny}
\setlength{\footnotesep}{0pt}
\ifnetbeamer@bold
    \setbeamerfont{frametitle}{size=\normalsize,series=\bfseries}
    \setbeamerfont{title}{series=\bfseries}
    \setbeamerfont{block title}{size={},series={\bfseries}}%
\else
    \setbeamerfont{frametitle}{size=\normalsize}
    \setbeamerfont{block title}{size={}}%
\fi
\ifnetbeamer@smooth
    \newcommand{\netbeamersep}{\hskip3pt~$\cdot$\hskip3pt}
    \setbeamertemplate{items}[circle]
    \setbeamertemplate{blocks}[rounded]
\else
    \newcommand{\netbeamersep}{\hskip3pt--\hskip3pt}
    \setbeamertemplate{items}[triangle]
    \setbeamertemplate{blocks}[default]
\fi
\setbeamercolor{normal text}{fg=TUMBlack,bg=TUMWhite}
\setbeamercolor{alerted text}{fg=TUMBeamerRed,bg=TUMWhite}
\setbeamercolor{example text}{fg=TUMBeamerGreen,bg=TUMWhite}
\setbeamercolor{frametitle}{fg=\netbeamer@basecolor,bg=TUMWhite}
\setbeamercolor{structure}{fg=\netbeamer@basecolor,bg=TUMWhite}
\ifnetbeamer@colorblock
    \setbeamercolor{block title}{fg=\netbeamer@basecolor,bg=\netbeamer@basecolor!7!TUMWhite}%
    \setbeamercolor{block body}{fg=TUMBlack,bg=\netbeamer@basecolor!7!TUMWhite}%
    \setbeamercolor{block title example}{fg=TUMBeamerGreen,bg=\netbeamer@basecolor!7!TUMWhite}%
    \setbeamercolor{block body example}{fg=TUMBlack,bg=\netbeamer@basecolor!7!TUMWhite}%
    \setbeamercolor{block title alerted}{fg=TUMBeamerRed,bg=\netbeamer@basecolor!7!TUMWhite}%
    \setbeamercolor{block body alerted}{fg=TUMBlack,bg=\netbeamer@basecolor!7!TUMWhite}%
\else
    \setbeamercolor{block title}{fg=\netbeamer@basecolor,bg=\netbeamer@basecolor}%
    \setbeamercolor{block body}{fg=TUMBlack,bg=TUMWhite}%
    \setbeamercolor{block title example}{fg=TUMBeamerGreen,bg=TUMBeamerGreen}%
    \setbeamercolor{block body example}{fg=TUMBlack,bg=TUMWhite}%
    \setbeamercolor{block title alerted}{fg=TUMBeamerRed,bg=TUMBeamerRed}%
    \setbeamercolor{block body alerted}{fg=TUMBlack,bg=TUMWhite}%
\fi

%----------------------------------------------------------------------
% Define some NET headline and footline templates
%
% headline templates:
%   no              nothing
%   fancy           net logo left, tum logo right, line
%   fancynoline     net logo left, tum logo right, no line
%
% footline templates:
%   no              nothing
%   minimal         frame number, no line
%   tum             tum foot, no line
%   tumline         tum foot with line
%   tumnet          tum -- net foot, no line
%   tumnetline      tum -- net foot, line
%   fancy           date, author, frame foot, line
%   fancyempty      empty foot, line
%   tumnetlogos     net logo left, tum logo right, no line
%   authortitleline   short author, short title, line
%
\defbeamertemplate*{headline}{no}{}
\defbeamertemplate*{footline}{no}{}
\defbeamertemplate*{footline}{minimal}{%
    \leavevmode%
    \hbox{%
        \begin{beamercolorbox}[wd=1.0\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{footline}{tum}{%
    \leavevmode%
    \hbox{%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm]{structure}%
            \relax% do nothing
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.90\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \TUMname\netbeamersep\@chair%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{footline}{net}{%
    \leavevmode%
    \hbox{%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm]{structure}%
            \relax% do nothing
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.90\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \TUMname\netbeamersep\@chair%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{footline}{tumline}{%
    \leavevmode%
    {\usebeamercolor[fg]{structure}\hrule height 0.5pt}%
    \vskip 1pt%
    \hbox{%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm]{structure}%
            \relax% do nothing
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.90\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \TUMname%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{footline}{netline}{%
    \leavevmode%
    {\usebeamercolor[fg]{structure}\hrule height 0.5pt}%
    \vskip 1pt%
    \hbox{%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm]{structure}%
            \relax% do nothing
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.90\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \TUMname\netbeamersep\@chair%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{headline}{fancy}{%
    \leavevmode%
    \hbox{%
        \begin{beamercolorbox}[wd=.5\paperwidth,ht=5.5mm,dp=1mm]{structure}%
            \hskip 2pt%
            \@logo{height=4.5mm,color=TUMDarkerBlue}
            \hskip 2pt%
            \textcolor{TUMDarkerBlue}{\fontsize{4.5pt}{4.5pt}\selectfont\@chair}%
%\begin{minipage}[b]{.3\paperwidth}
%            \textcolor{TUMDarkerBlue}{\fontsize{4.5pt}{4.5pt}\selectfont%
%Department of Computer Science}%
%
%            \textcolor{TUMDarkerBlue}{\fontsize{4.5pt}{4.5pt}\selectfont%
%Chair for Network Architectures and Services}%
%\end{minipage}
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.5\paperwidth,ht=5mm,dp=1mm,right]{structure}%
            \textcolor{TUMDarkerBlue}{\fontsize{4.5pt}{4.5pt}\selectfont\TUMname}%
            \hskip 2pt%
            \TUMlogo{height=4.5mm,color=TUMDarkerBlue}%
            \hskip 2pt\mbox{}%
        \end{beamercolorbox}%
    }%
    {\usebeamercolor[fg]{structure}\hrule height 0.5pt}%
    \vskip 0.5pt%
    \vskip 0pt%
}
\defbeamertemplate*{footline}{fancy}{%
    \leavevmode%
    {\usebeamercolor[fg]{structure}\hrule height 0.5pt}%
    \vskip 1pt%
    \hbox{%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm]{structure}%
            \relax% do nothing
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.90\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertshortdate\netbeamersep%
            \insertshortauthor\netbeamersep%
            \insertshorttitle%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{headline}{fancynoline}{%
    \leavevmode%
    \hbox{%
        \begin{beamercolorbox}[wd=.5\paperwidth,ht=5mm,dp=1mm]{structure}%
            \hskip 2pt%
            \@logo{height=4.5mm,color=TUMBlue}%
            \hskip 2pt%
            \textcolor{TUMBlue}{\fontsize{4.5pt}{4.5pt}\selectfont\@chair}%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.5\paperwidth,ht=5mm,dp=1mm,right]{structure}%
            \textcolor{TUMBlue}{\fontsize{4.5pt}{4.5pt}\selectfont\TUMname}%
            \hskip 2pt%
            \TUMlogo{height=4.5mm,color=TUMBlue}%
            \hskip 2pt\mbox{}%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{footline}{fancyempty}{%
    \leavevmode%
    {\usebeamercolor[fg]{structure}\hrule height 0.5pt}%
    \vskip 1pt%
    \hbox{%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm]{structure}%
            \phantom{%
                \insertshortdate\netbeamersep%
                \insertshortauthor\netbeamersep%
                \insertshorttitle%
            }%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.90\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \phantom{%
                \insertshortdate\netbeamersep%
                \insertshortauthor\netbeamersep%
                \insertshorttitle%
            }%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \phantom{\insertframenumber}%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{footline}{tumnetlogos}{%
    \leavevmode%
    \hbox{%
        \begin{beamercolorbox}[wd=.5\paperwidth,ht=2mm,dp=1mm]{structure}%
            \hskip 2pt%
            \@logo{height=4.5mm,color=TUMBlue}%
            \hskip 2pt%
            \textcolor{TUMBlue}{\fontsize{4.5pt}{4.5pt}\selectfont\@chair}%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.5\paperwidth,ht=2mm,dp=1mm,right]{structure}%
            \textcolor{TUMBlue}{\fontsize{4.5pt}{4.5pt}\selectfont\TUMname}%
            \hskip 2pt%
            \TUMlogo{height=4.5mm,color=TUMBlue}%
            \hskip 2pt\mbox{}%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}
\defbeamertemplate*{footline}{lecture}{%
    \leavevmode%
    {\usebeamercolor[fg]{structure}\hrule height 0.5pt}%
    \vskip 1pt%
    \hbox{%
        \begin{beamercolorbox}[wd=.95\paperwidth,ht=2mm,dp=1mm]{structure}%
            \hskip2ex%
            \fontsize{4.5pt}{4.5pt}\selectfont\@moduleshorttitle\ (\@modulenumber)%
            \ifx\@empty\insertsectionhead%
                {}%
            \else%
                {:\ \insertsectionhead}%
            \fi%
            \ifx\@empty\insertsubsectionhead%
                {}%
            \else%
                {\ -- \ \insertsubsectionhead}%
            \fi%
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}

\defbeamertemplate*{footline}{authortitleline}{%
    \leavevmode%
    {\usebeamercolor[fg]{structure}\hrule height 0.5pt}%
    \vskip 1pt%
    \hbox{%
        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm]{structure}%
            \relax% do nothing
        \end{beamercolorbox}%
        \begin{beamercolorbox}[wd=.90\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertshortauthor\netbeamersep\insertshorttitle%
        \end{beamercolorbox}%

        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}

\defbeamertemplate*{footline}{titlesectionline}{%
    \leavevmode%
    {\usebeamercolor[fg]{structure}\hrule height 0.5pt}%
    \vskip 1pt%
    \hbox{%
        \begin{beamercolorbox}[wd=.95\paperwidth,ht=2mm,dp=1mm,left]{structure}%
            \hskip1mm\insertshorttitle%
			\ifx\@empty\insertsectionhead%
				\relax%
			\else\netbeamersep\insertsectionhead%
			\fi%
			\ifx\@empty\insertsubsectionhead%
				\relax%
			\else:\ \insertsubsectionhead%
			\fi%
        \end{beamercolorbox}%

        \begin{beamercolorbox}[wd=.05\paperwidth,ht=2mm,dp=1mm,center]{structure}%
            \insertframenumber%
        \end{beamercolorbox}%
    }%
    \vskip 0pt%
}

%----------------------------------------------------------------------
% Define netblock environment
%
\definecolor{netbeamer@block@titlecolor}{named}{TUMBlack}
\definecolor{netbeamer@block@textcolor}{named}{TUMBlack}
\definecolor{netbeamer@block@rulecolor}{named}{TUMBlack}
\definecolor{netbeamer@block@bgcolor}{named}{TUMWhite}
\newlength{\netbeamer@block@rule}\setlength{\netbeamer@block@rule}{1pt}
\newlength{\netbeamer@block@sep}\setlength{\netbeamer@block@sep}{7pt}
\newlength{\netbeamer@block@titlesep}\setlength{\netbeamer@block@titlesep}{0pt}
\newlength{\netbeamer@block@textwidth}
\newsavebox{\netbeamer@block@content}
\newenvironment{netbeamer@block}[1]{%
    \setlength{\fboxrule}{\netbeamer@block@rule}%
    \setlength{\fboxsep}{\netbeamer@block@sep}%
    \setlength{\netbeamer@block@textwidth}{\textwidth}%
    \addtolength{\netbeamer@block@textwidth}{-2\netbeamer@block@rule}%
    \addtolength{\netbeamer@block@textwidth}{-2\netbeamer@block@sep}%
    \begin{lrbox}{\netbeamer@block@content}%
        \hbox\bgroup\begin{minipage}{\netbeamer@block@textwidth}\begin{flushleft}%
        \vskip 0pt%
        \isempty{#1}%
        \ifempty
        \vskip 0pt%
        \else%
            {\usebeamerfont*{block title}\color{netbeamer@block@titlecolor}#1}\vskip\netbeamer@block@titlesep%
        \fi%
        \color{netbeamer@block@textcolor}%
}{%
    %\vskip -4pt \vskip 4pt%
    \end{flushleft}\end{minipage}\egroup\end{lrbox}%
    % draw the whole thing
    \ifnetbeamer@colorblock
        \colorbox{netbeamer@block@bgcolor}{\usebox{\netbeamer@block@content}}%
    \else
        \fcolorbox{netbeamer@block@rulecolor}{netbeamer@block@bgcolor}{\usebox{\netbeamer@block@content}}%
    \fi
}
\renewenvironment{block}[1]{%
    \usebeamercolor{block title}
    \definecolor{netbeamer@block@titlecolor}{named}{fg}%
    \definecolor{netbeamer@block@rulecolor}{named}{bg}%
    \usebeamercolor{block body}
    \definecolor{netbeamer@block@textcolor}{named}{fg}%
    \definecolor{netbeamer@block@bgcolor}{named}{bg}%
    \begin{netbeamer@block}{#1}%
}{%
    \end{netbeamer@block}%
}%
\renewenvironment{exampleblock}[1]{%
    \usebeamercolor{block title example}
    \definecolor{netbeamer@block@titlecolor}{named}{fg}%
    \definecolor{netbeamer@block@rulecolor}{named}{bg}%
    \usebeamercolor{block body example}
    \definecolor{netbeamer@block@textcolor}{named}{fg}%
    \definecolor{netbeamer@block@bgcolor}{named}{bg}%
    \begin{netbeamer@block}{#1}%
}{%
    \end{netbeamer@block}%
}%
\renewenvironment{alertblock}[1]{%
    \usebeamercolor{block title alerted}
    \definecolor{netbeamer@block@titlecolor}{named}{fg}%
    \definecolor{netbeamer@block@rulecolor}{named}{bg}%
    \usebeamercolor{block body alerted}
    \definecolor{netbeamer@block@textcolor}{named}{fg}%
    \definecolor{netbeamer@block@bgcolor}{named}{bg}%
    \begin{netbeamer@block}{#1}%
}{%
    \end{netbeamer@block}%
}%

%----------------------------------------------------------------------
% Default title frames
%
\newcommand\maketitleframe{%
\centering%
\LARGE{\textcolor{TUMDarkerBlue}\inserttitle}

\normalsize%
\textcolor{TUMDarkerBlue}{\insertsubtitle}

\vskip4ex
\bfseries{\insertauthor}

\vskip4ex
\normalfont\scriptsize
\insertdate

\vskip4ex
\@chair\\
\@department\\
\TUMname\\
}

\newcommand\makelecturetitleframe[4]{%
\centering%

\isequal{\@lecturetitle}{\@empty}\ifequal

\LARGE{\textcolor{TUMDarkerBlue}{\@moduletitle\ (\@modulenumber)}}%
\vskip.5ex%
\normalsize%
\@term

\else

\LARGE{\textcolor{TUMDarkerBlue}{\@lecturetitle}}\\
\vskip1ex%
\scriptsize%
\@modulenumber: \@moduletitle\\
\@term
\normalsize%
\fi

\vskip2ex%

\isequal{#2}{\@empty}\ifequal

\vskip2ex%

\bfseries{\@lecturer}%

\bfseries{#1}

\vskip4ex%
\normalfont
\scriptsize%
\@chair\\
\@department\\
\TUMname

\else
\TUMname

\vskip2ex%

\scriptsize%
\@department\\
\@chair\\
\bfseries{\@lecturer, #1}%

\vskip2ex%

\normalfont%
#3\\
#4\\
\bfseries{#2}%
\fi
}

%----------------------------------------------------------------------
% Set beamertemplates depending on supplied options
%
\ifnetbeamer@lecture
    \setbeamertemplate{headline}[fancy]
    \setbeamertemplate{footline}[lecture]
    \setbeamerfont{section in toc}{size=\scriptsize}
    \setbeamerfont{subsection in toc}{size=\tiny}
    \renewcommand\maketitleframe[4]{\makelecturetitleframe{#1}{#2}{#3}{#4}}
\else
    \setbeamertemplate{headline}[fancy]
    \setbeamertemplate{footline}[netline]
\fi

\endinput
