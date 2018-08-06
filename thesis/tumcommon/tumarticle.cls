%
% tumarticle.cls
%

%----------------------------------------------------------------------
% Identify class
%
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{tumarticle}%
    [2016/05/19 v0.1 %
    tumarticle.cls article class]

%----------------------------------------------------------------------
% Class options
%
\DeclareOption*{\PassOptionsToPackage{\CurrentOption}{tumlang}}%
\ProcessOptions\relax

\LoadClassWithOptions{article}
\RequirePackage{tumcolor}
\RequirePackage{tumcontact}
\RequirePackage{tumlang}
\RequirePackage{xparse}
\RequirePackage[pagestyles]{titlesec}
\RequirePackage{geometry}

\newgeometry{%
	top		= 3cm,
	left		= 2cm,
	right		= 2cm,
	bottom		= 3cm,
	headheight	= 1cm,
	headsep		= 1cm,
	footskip	= 2cm,
}

\newpagestyle{tumarticle}{%
	\sethead{}{\TUMheader{1cm}}{}
	\setfoot{}{{\footnotesize\TUMfooter*}}{}
}
\newpagestyle{tumarticlenopagenumber}{%
	\sethead{}{\TUMheader{1cm}}{}
	\setfoot{}{\footnotesize\TUMfooter}{}
}
\pagestyle{tumarticle}

\renewcommand\title[2][]{%
	\ifx#1\@empty\@empty
		\edef\thetitle{#2}
		\edef\@title{#2}
	\else
		\expandafter\expandafter\expandafter%
			\addto\expandafter\expandafter\csname captions#1\endcsname{%
			\def\thetitle{#2}
			\def\@title{#2}
		}
	\fi
}

\newcommand\subtitle[2][]{%
	\ifx#1\@empty\@empty
		\edef\thesubtitle{#2}
	\else
		\expandafter\expandafter\expandafter%
			\addto\expandafter\expandafter\csname captions#1\endcsname{%
			\def\thesubtitle{#2}
		}
	\fi
}

\endinput
