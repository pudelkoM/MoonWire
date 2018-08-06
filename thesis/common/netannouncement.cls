%
% netannouncement.cls
%
%

%----------------------------------------------------------------------
% Identify class
%
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{netannouncement}%
    [2015/01/18 v0.01.0 %
    netthesis.cls NET announcement class]

%----------------------------------------------------------------------
% Class options
%
\RequirePackage{kvoptions}%
\SetupKeyvalOptions{family=netannouncement,prefix=netannouncement@}%
% netcommon.sty
\DeclareVoidOption{english}{\PassOptionsToPackage{netcommon}{english}}%
\DeclareVoidOption{ngerman}{\PassOptionsToPackage{netcommon}{ngerman}}%
\DeclareVoidOption{german}{\PassOptionsToPackage{netcommon}{german}}%
% special declarations
\DeclareBoolOption[false]{idp}
\DeclareBoolOption[false]{hiwi}
\DeclareBoolOption[false]{guidedresearch}
\DeclareBoolOption[false]{bachelor}
\DeclareBoolOption[false]{master}
\DeclareBoolOption[false]{gamesengineering}
% special undocumented release option to avoid white border
\DeclareBoolOption[false]{noprint}
% Process options
\ProcessKeyvalOptions*\relax

%----------------------------------------------------------------------
% Load base class report and required packages
%
\LoadClassWithOptions{article}
\RequirePackage{geometry}
\RequirePackage{netcommon}
\RequirePackage{setspace}
\RequirePackage{graphics}
\RequirePackage{ifthen}
\RequirePackage{calc}
\RequirePackage{tabularx}
\RequirePackage{multirow}
\RequirePackage{qrcode}
\RequirePackage[hidelinks]{hyperref}

% tikz
\RequirePackage{tikz}
\usetikzlibrary{shapes} 
\usetikzlibrary{positioning}

% font
\RequirePackage{helvet}
\renewcommand{\familydefault}{\sfdefault}
\fontfamily{phv}\selectfont

% lists
\RequirePackage{enumitem}
\setlist[itemize]{leftmargin=*, topsep=0pt, partopsep=0pt, parsep=0pt, itemsep=5pt}
% itemize, item style
\let\olditem\item
\renewcommand{\item}{\olditem[\textcolor{TUMDarkerBlue}{\rule{5pt}{5pt}}] }

%----------------------------------------------------------------------
% Page geometry
%
\geometry{textwidth=\paperwidth, textheight=\paperheight, noheadfoot, nomarginpar}
\setlength{\topskip}{0mm}
\setlength{\parindent}{0mm}

%----------------------------------------------------------------------
% Macros
%

% fix for lazy people incapable of using href
\renewcommand{\url}[1]{\href{#1}{#1}}

% header & decoration of page
\newcommand{\pageTopOffset}{1.395cm} % distance between top of page & middle of header
\newcommand{\pageTextOffset}{3.65cm} % distance between left of page & text block
\newcommand{\pageLeftOffset}{2.79cm} % width of decoration to the left of page
\newcommand{\pageFooterOffset}{0.25cm} % height of decoration below footer image
\newcommand{\pageFooterColor}{TUMDarkerBlue} % color of decoration below footer image

\newcommand{\logoHeight}{2.19cm}
\newcommand{\logoDistance}{0.6cm} % margin around logo
\newcommand{\logoLeftOffset}{0cm} % distance of page and logo
\newcommand{\logoColor}{white}
\newcommand{\logoBackgroundColor}{TUMDarkerBlue}

\newcommand{\headerHeight}{2.79cm} % height of header decoration
\newcommand{\headerTitleLeftOffset}{3cm} % left offset of text in header decoration
\newcommand{\headerTitleWidth}{16cm} % width of title

\ifthenelse{\boolean{netannouncement@noprint}}{
	\newcommand{\outerRim}{.0cm} 
}{
	\newcommand{\outerRim}{.5cm} 
}

\newcommand{\widthSegmentTitle}{4cm} % width of headline of each segment
\newcommand{\widthTextPart}{\textwidth - 1.75cm - (\widthSegmentTitle) - \outerRim} % width of textpart



\newcommand\titlepagedecoration{
\begin{tikzpicture}[remember picture,overlay,shorten >= -10pt]

	% left page decoration
	\node at ([xshift=\pageLeftOffset / 2+\outerRim] current page.west) [color=white, fill=TUMDarkerBlue!10, rectangle, minimum height=\paperheight-2*\outerRim, minimum width=\pageLeftOffset] {};
	
	% header
	\node (chair) at ([yshift=\pageTopOffset-\headerHeight/2-\outerRim,xshift=\outerRim] current page.north west) [outer sep=0pt, inner sep=0pt, color=white, fill=TUMDarkerBlue, rectangle, minimum height=\headerHeight, minimum width=21cm-2*\outerRim, text width=21cm-2*\outerRim, anchor=north west] {	
		\begin{tabular}{@{}p{\headerTitleLeftOffset}@{}p{\headerTitleWidth}@{}}
			&{\TUMname , \INname} \vfill \\
			&{\LARGE \NETname} \\
			&{\NEThead}\\
		\end{tabular}
	};		
	
	% logo
	\node at ([xshift=\logoLeftOffset + \logoDistance / 2 + \logoHeight / 2+\outerRim, yshift=-\pageTopOffset-\outerRim] current page.north west) [minimum height=\logoHeight, minimum width=\logoHeight] {\NETlogo{height=\logoHeight, color=\logoColor}};		
	
	\pgfmathsetmacro{\pos}{8cm}
	
	%check if most right position is to be filled
	\ifthenelse{\boolean{netannouncement@idp} \or \boolean{netannouncement@hiwi} \or \boolean{netannouncement@guidedresearch}}{
		%HiWi, guided research or IDP is given
		\node at ([xshift=\pos,yshift=-0.7cm] chair.south) [inner sep=0pt, starburst,fill=TUMBeamerYellow,text=white,rotate=-7,inner sep=0pt,outer sep=0pt,minimum height=3cm,minimum width=4cm] {\textbf{\begin{tabular}{c}
		% ugly code but necessary to avoid spaces between selections
		\ifthenelse{\boolean{netannouncement@idp} \OR \boolean{netannouncement@hiwi}}{
			\ifthenelse{\boolean{netannouncement@idp} \and \boolean{netannouncement@hiwi}}{IDP, HiWi}{\ifthenelse{\boolean{netannouncement@idp}}{IDP}{HiWi}}\ifthenelse{\boolean{netannouncement@guidedresearch}}{,\\}{}
	 	}{}
	 	\ifthenelse{\boolean{netannouncement@guidedresearch}}{
	 		Guided\\ Research\\
	 	}{}
	 	\end{tabular}}};	
		\pgfmathsetmacro{\pos}{\pos - 2.7cm}
	}{}		
				
	\ifnetannouncement@gamesengineering
	\ifnet@german
		\node at ([xshift=\pos,yshift=-0.55cm] chair.south) [inner sep=0pt, starburst,fill=TUMMediumGray,text=white,rotate=-10.5,minimum height=2.9cm] { \textbf{\begin{tabular}{@{}c@{}}GE\\Praktikum\end{tabular}}};	
	\else 
			\node at ([xshift=\pos,yshift=-0.6cm] chair.south) [inner sep=0pt, starburst,fill=TUMMediumGray,text=white,rotate=-10] { \textbf{\begin{tabular}{c} GE\\Practical\\Course\end{tabular}}};	
	\fi
		\pgfmathsetmacro{\pos}{\pos - 2.7cm}		
	\fi			
		
	\ifnetannouncement@master
		\node at ([xshift=\pos,yshift=-0.6cm] chair.south) [inner sep=0pt, starburst,fill=TUMGreen,text=white,rotate=-10] {\large \textbf{\begin{tabular}{c} Thesis\\ M.Sc.\end{tabular}}};	
		\pgfmathsetmacro{\masterpos}{\pos}
		\pgfmathsetmacro{\pos}{\pos - 2.6cm}
	\fi
				
	\ifnetannouncement@bachelor
		\node at ([xshift=\pos,yshift=-0.6cm] chair.south) [inner sep=0pt, starburst,fill=TUMOrange,text=white,rotate=-10] {\large \textbf{\begin{tabular}{c} Thesis\\ B.Sc.\end{tabular}}};
		\pgfmathsetmacro{\pos}{\pos - 2.6cm}
	\fi	
				
	\ifnetannouncement@master
		\node at ([xshift=\masterpos,yshift=-0.6cm] chair.south) [inner sep=0pt, starburst,fill=TUMGreen,text=white,rotate=-10] {\large \textbf{\begin{tabular}{c} Thesis\\ M.Sc.\end{tabular}}};	
	\fi
	
	%footer
	\node(footer) at (10.5cm,-28.94cm+\pageFooterOffset+\outerRim) {\includegraphics[height=1.54cm,width=21cm-\outerRim-\outerRim]{footer.png}}; 
	\ifthenelse{\equal{\pageFooterOffset}{0cm}}{
		%do nothing if footer should be of height 0
	}{
		\node(below footer) at (10.5cm,-29.7cm+\pageFooterOffset/2+\outerRim) [rectangle, minimum height=\pageFooterOffset, minimum width=21cm-2*\outerRim, fill=\pageFooterColor] {};
	}
	 	
\end{tikzpicture}

\vspace{\pageTextOffset}

}

% text block with title node
\newcommand\segment[2]{
\begin{tikzpicture}
\begin{scope}
	\node (textpart) at (0,0) [text width=\widthTextPart, text justified, inner sep=0, outer sep=0] {\begin{minipage}{\textwidth}#2\end{minipage}
	
	};
	\node (seg) at ([xshift=-((\textwidth - (\widthSegmentTitle+\widthTextPart))/2),yshift=.2ex] textpart.north west) [anchor=north east, outer sep=0pt, inner sep=0pt, color=white, fill=TUMDarkerBlue, rectangle, minimum height=1cm, minimum width=\widthSegmentTitle, text width = \widthSegmentTitle-1cm] {\textbf{#1}};
	\node at (seg.west) [anchor=east, inner sep=0pt, outer sep=0pt, minimum width=\outerRim] {};
\end{scope}
\end{tikzpicture}
\vspace{0.5cm}
}

% segment without title node
% arg0 text of headline
\newcommand\headline[1]{
	\newcounter{cnt}	
	%check if most right position is to be filled
	\ifthenelse{\boolean{netannouncement@idp} \or \boolean{netannouncement@hiwi} \or \boolean{netannouncement@guidedresearch}}{
		\stepcounter{cnt}
	}{}		
	\ifnetannouncement@master
		\stepcounter{cnt}
	\fi
	\ifnetannouncement@bachelor
		\stepcounter{cnt}
	\fi
	\ifnetannouncement@gamesengineering
		\stepcounter{cnt}
	\fi
	\ifnum\value{cnt}=0	\head{#1}{0.00001cm} \fi
	\ifnum\value{cnt}=1	\head{#1}{3cm} \fi
	\ifnum\value{cnt}=2	\head{#1}{6cm} \fi
	\ifnum\value{cnt}=3	\head{#1}{9cm} \fi
	\ifnum\value{cnt}=4	\head{#1}{12cm} \fi
}

% headline with linebreak to keep starbursts clean
%
% arg0 text of headline
% arg1 free space on the left of the first line of the headline
%
\newcommand\head[2]{
\begin{tikzpicture}
\begin{scope}
	\node (textpart) at (0,-\outerRim) [inner ysep=\outerRim, inner xsep=0, text width=\widthTextPart] {	

	\begin{wrapfigure}[1]{r}{#2}
	\captionsetup{labelformat=empty}
	\caption{}
	\end{wrapfigure}#1

	};	
	\node (seg) at ([xshift=-((\textwidth - (\widthSegmentTitle+\widthTextPart))/2),yshift=.2ex] textpart.north west) [anchor=north east, outer sep=0pt, inner sep=0pt, color=white, fill=none, rectangle, minimum height=1cm, minimum width=\widthSegmentTitle, text width = \widthSegmentTitle-1cm] {};
	\node at (seg.west) [anchor=east, inner sep=0pt, outer sep=0pt, minimum width=\outerRim] {};
\end{scope}
\end{tikzpicture}
\vspace{0.5cm}
}

% contacts with optional qr code
\newcommand\contact[2][]{
	\segment{\ifnet@german Kontakt \else Contact \fi}{
\ifthenelse{\equal{#1}{}}{
	\begin{tabularx}{\textwidth}{@{}p{\textwidth}@{}}
		{#2}\\
	\end{tabularx}
}{
	\begin{tabularx}{\textwidth}{@{}p{\textwidth-2cm-\outerRim}@{}@{}r@{}}
		{#2}&\qrcode[height=2cm]{#1}\\
	\end{tabularx}
}
	}
	\vspace{\outerRim}
	\vspace{1.5cm}
	\vspace{\pageFooterOffset}
}