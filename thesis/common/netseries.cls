%
% netseries.cls
%
%

%----------------------------------------------------------------------
% Identify class
%
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{netseries}%
    [2015/10/01 v0.01.1 %
    netseries.cls NET class for proceedings/dissertations]

%----------------------------------------------------------------------
% Class options
%
\RequirePackage{kvoptions}%
\SetupKeyvalOptions{family=netseries,prefix=netseries@}%
% netcommon.sty
\DeclareVoidOption{ngerman}{\PassOptionsToPackage{netcommon}{ngerman}}%
\DeclareVoidOption{german}{\PassOptionsToPackage{netcommon}{german}}%
% document type
\DeclareStringOption[plain]{document}
\DeclareVoidOption{dissertation}{\renewcommand\netseries@document{dissertation}}
\DeclareVoidOption{proceedings}{\renewcommand\netseries@document{proceedings}}
% with or without footer picture
\DeclareBoolOption[false]{footerpicture}
\DeclareBoolOption[false]{print}
% Process options
\ProcessKeyvalOptions*\relax

%----------------------------------------------------------------------
% Load base class report and required packages
%
\LoadClassWithOptions{article}
\RequirePackage{xifthen}
\RequirePackage[a4paper]{geometry}
\RequirePackage{netcommon}
\RequirePackage{setspace}
\RequirePackage{graphics}
\RequirePackage{calc}
\RequirePackage{tabularx}
\RequirePackage{multirow}
\RequirePackage{hyperref}
\RequirePackage{adjustbox}
\RequirePackage{ean13isbn}

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

%----------------------------------------------------------------------
% Page geometry
%
\geometry{textwidth=\paperwidth, textheight=\paperheight, noheadfoot, nomarginpar}
\setlength{\topskip}{0mm}
\setlength{\parindent}{0mm}

%----------------------------------------------------------------------
% Macros
%

% header & decoration of page
\newcommand{\tClipping}{4mm} % distance between top of page and header
\newcommand{\bClipping}{4mm} % distance between bottom of page and footer
\newcommand{\rClipping}{4mm} % distance between right of page and text (only for front page) 
\newcommand{\lClipping}{4mm} % distance between left of page and text (only for back page)
\newcommand{\joint}{5mm} % distance between left of page (joint == falz) and text 

\newcommand{\pageTopOffset}{1.25cm} % distance between top of page & middle of header
\newcommand{\pageHeaderFooterColor}{TUMBlue} % color of decoration below footer image
\newcommand{\pageBackgroundColor}{\pageHeaderFooterColor!20} % width of decoration to the left of page
\newcommand{\pageLeftOffset}{3.3cm} % width of decoration to the left of page

\newcommand{\logoHeaderHeight}{1.75cm}
\newcommand{\logoFooterHeight}{1.5cm}
\newcommand{\logoXDistance}{1cm} % margin on the left and right side of the logos
\newcommand{\logoColor}{white}

\newcommand{\headerHeight}{2.8cm} % height of header decoration
\newcommand{\footerHeight}{2.2cm} % height of decoration below footer image

% decoration settings depending on document type
\isequal{\netseries@document}{dissertation}
\ifequal
	\newcommand{\widthSegmentTitle}{2.8cm} % width of headline of each segment
	\newcommand{\pageTextOffset}{5cm} % distance between left of page & text block
\fi
\isequal{\netseries@document}{proceedings}
\ifequal
	\newcommand{\widthSegmentTitle}{4cm} % width of headline of each segment
	\newcommand{\pageTextOffset}{5cm} % distance between left of page & text block
\fi
\newcommand{\widthTextPart}{21cm-\widthSegmentTitle-\rClipping} % width of textpart

% item style
\let\olditem\item
\renewcommand{\item}{\olditem[\textcolor{\pageHeaderFooterColor}{\rule{5pt}{5pt}}] }

% decoration of title page (header, footer etc.)
% arg0: NET series volume
\newcommand\titlepagedecoration[1]{

\begin{tikzpicture}[remember picture,overlay]

	% background
	\node at (current page.north east) [anchor=north east, fill=\pageBackgroundColor, draw=\pageBackgroundColor, rectangle, minimum height=\paperheight, minimum width=\paperwidth] {};
			
	% top and bottom clippings	
	\node (topClipping) at (current page.north east) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\tClipping, minimum width=\paperwidth, anchor=north east] {};	
	\node (bottomClipping) at (current page.south) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\bClipping, minimum width=\paperwidth, anchor=south] {};
	\node (rightClipping) at ([yshift=\bClipping/2-\tClipping/2] current page.east) [outer sep=0pt, inner sep=0pt, draw=white, fill=white, rectangle, minimum height=\paperheight-\tClipping-\bClipping, minimum width=\rClipping,opacity=0,anchor=east] {};
	
	% partially white title page
	\node at (rightClipping.north east) [anchor=north east, fill=white, draw=white, rectangle, minimum height=\paperheight-\tClipping-\bClipping-\footerHeight, minimum width=21cm-\pageLeftOffset] {};
	\node (rightClipping) at ([yshift=\bClipping/2-\tClipping/2] current page.east) [outer sep=0pt, inner sep=0pt, draw=white, rectangle, minimum height=\paperheight-\bClipping-\tClipping, minimum width=\rClipping,anchor=east] {};
			
	% header
	\node (headercolored) at (rightClipping.north east) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\headerHeight, minimum width=\paperwidth, anchor=north east] {};	
	\node (header) at (rightClipping.north west) [outer sep=0pt, inner sep=0pt, color=white, rectangle, minimum height=\headerHeight, minimum width=21cm-\rClipping-\joint, text width=21cm-\rClipping-\joint, anchor=north east] {};
	\node (netlogo) at (header.west) [outer sep=0pt, inner ysep=0pt, inner xsep=\logoXDistance/2, color=white, rectangle, anchor=west] {\NETlogo{height=\logoHeaderHeight,color=white}};
	\node (nettext) at (netlogo.east) [outer sep=0pt, inner xsep=.25cm, inner ysep=0pt, minimum height=\logoHeaderHeight, text width=7cm, color=white, rectangle, anchor=west] {{\large Network Architectures\\ and Services \\ #1\\} };
	
	% type of document (dissertation/proceedings)
	\node at (header.east) [align=center, outer sep=0pt, inner sep=0pt, color=white, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\headerHeight, minimum width=(21cm-\pageLeftOffset-\rClipping)/2, anchor=east] {
	\isequal{\netseries@document}{dissertation}
	\ifequal
		\LARGE
		Dissertation
	\fi
	\isequal{\netseries@document}{proceedings}
	\ifequal
		\LARGE
		Proceedings
	\fi
	};		
		
	% header separator		
	\draw[color=white, line width=0.8pt] ([xshift=\pageLeftOffset/2-\rClipping, yshift=-((\headerHeight-\logoHeaderHeight)/2)] header.north) -- ([xshift=\pageLeftOffset/2-\rClipping, yshift=((\headerHeight-\logoHeaderHeight)/2)] header.south);	
		
		
	%footer
	\ifthenelse{\equal{\footerHeight}{0cm}}{
		%do nothing if footer should be of height 0
	}{
		\node(footercolored) at (rightClipping.south east) [rectangle, minimum height=\footerHeight, minimum width=\paperwidth, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, inner sep=0pt, outer sep=0pt, anchor=south east] {};
		\node(footer) at (rightClipping.south west) [rectangle, minimum height=\footerHeight, minimum width=21cm-\rClipping-\joint, text width=21cm-\rClipping-\joint,inner sep=0pt,anchor=south east] {};
		\node (inlogo) at ([xshift=\logoHeaderHeight - \logoFooterHeight+\joint, yshift=(\footerHeight-\logoFooterHeight)/2] bottomClipping.north west) [outer sep=0pt, inner ysep=0pt, inner xsep=\logoXDistance/2, color=white, rectangle, anchor=south west] {\INlogo{height=\logoFooterHeight,color=white}};
		\node (intext) at (inlogo.base east) [outer sep=0pt, inner xsep=.25cm, inner ysep=0pt, minimum height=\logoFooterHeight, text width=7cm, color=white, rectangle, anchor=base west] {\parbox[b][\logoFooterHeight]{13cm}{\INname}};
		\node (tumlogo) at ([yshift=(\footerHeight-\logoFooterHeight)/2] rightClipping.south west) [outer sep=0pt, inner ysep=0pt, inner xsep=\logoXDistance/2, color=white, rectangle, anchor=south east] {\TUMlogo{height=\logoFooterHeight,color=white, shape=outline}};
		\node (tumtext) at (tumlogo.base west) [outer sep=0pt, inner sep=0pt, minimum height=\logoFooterHeight, text width=7cm, color=white, rectangle, anchor=base east] {\parbox[b][\logoFooterHeight]{7cm}{\hfill\TUMname}};
	}

	\ifthenelse{\boolean{netseries@footerpicture}}{
		\node(footerpicture) at (footercolored.north east) [anchor=south east,outer sep=0pt, inner sep=0pt] {\includegraphics[height=1.54cm,width=21cm]{footer.png}};
	}{}

\end{tikzpicture}

\vspace{\pageTextOffset}
}

% decoration of title page (header, footer etc.)
% arg0: ISBN
% arg1: DOI
% arg2: ISSN
% arg3: ISSN
\newcommand\backpagedecoration[4]{

\begin{tikzpicture}[remember picture,overlay]
	
	% background
	\node at (current page.north east) [anchor=north east, fill=\pageBackgroundColor, draw=\pageBackgroundColor, rectangle, minimum height=\paperheight, minimum width=\paperwidth] {};
			
	% top and bottom clippings	
	\node (topClipping) at (current page.north east) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\tClipping, minimum width=\paperwidth, anchor=north east] {};	
	\node (bottomClipping) at (current page.south) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\bClipping, minimum width=\paperwidth, anchor=south] {};
	\node (leftClipping) at ([yshift=\bClipping/2-\tClipping/2] current page.west) [outer sep=0pt, inner sep=0pt, draw=\pageBackgroundColor, fill=\pageBackgroundColor, rectangle, minimum height=\paperheight-\bClipping-\tClipping, minimum width=\lClipping,opacity=0,anchor=west] {};
			
	% header
	\node (headercolored) at (leftClipping.north west) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\headerHeight, minimum width=\paperwidth, anchor=north west] {};	
			
	%footer
	\ifthenelse{\equal{\footerHeight}{0cm}}{
		%do nothing if footer should be of height 0
	}{
		\node(footercolored) at (leftClipping.south west) [rectangle, minimum height=\footerHeight, minimum width=\paperwidth, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, inner sep=0pt, outer sep=0pt, anchor=south west] {};
	\node(footer) at (leftClipping.south east) [rectangle, minimum height=\footerHeight, minimum width=21cm-\lClipping, text width=21cm-\lClipping,inner sep=0pt,anchor=south west] {};
	\node (inlogo) at ([xshift=\logoXDistance/2, yshift=-0.2cm] footer.north west) [outer sep=0pt, inner sep=3pt, color=\pageHeaderFooterColor, rectangle, anchor=north west,fill=white] {
			\EANisbn[SC0,ISBN=#1]
		};
	%\node (intext) at ([yshift=3pt] inlogo.east) [outer sep=0pt, inner sep=0pt, minimum height=\logoFooterHeight, text width=7cm, color=white, rectangle, anchor=west] {\parbox[b][\logoFooterHeight]{13cm}{\begin{tabular}{ll}	
	%DOI & #2\\	
	%ISSN & #3 (print)\\
	%ISSN & #4 (electronic)\\
	%\end{tabular}}};
	}

	%\node(isbn) at ([xshift=1cm, yshift=3cm]leftClipping.south west) [color=\pageHeaderFooterColor, rectangle, inner sep=2pt, outer sep=0pt, anchor=south west] {\EAN #1};		
	\node(isbn) at ([xshift=\logoXDistance/2+\lClipping, yshift=\footerHeight+0.3cm]leftClipping.south west) [color=\pageHeaderFooterColor, rectangle, inner ysep=2pt, outer sep=0pt, anchor=south west] {\begin{tabular}{@{}ll}
ISBN & #1\\	
DOI & #2\\
\\
ISSN & #3 (print)\\
ISSN & #4 (electronic)
	\end{tabular}};		

\end{tikzpicture}
}

% spine (buchrücken) decoration
% arg0 title
\newcommand\spinedecoration[1]{
\begin{tikzpicture}[remember picture,overlay]
	
	% background
	\node at (current page.north east) [anchor=north east, fill=\pageBackgroundColor, draw=\pageBackgroundColor, rectangle, minimum height=\paperheight, minimum width=\paperwidth] {};
			
	% top and bottom clippings	
	\node (topClipping) at (current page.north east) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\tClipping, minimum width=\paperwidth, anchor=north east] {};	
	\node (bottomClipping) at (current page.south) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\bClipping, minimum width=\paperwidth, anchor=south] {};			
			
	% header
	\node (headercolored) at (current page.north west) [outer sep=0pt, inner sep=0pt, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, rectangle, minimum height=\headerHeight, minimum width=\paperwidth, anchor=north west] {};	
			
	%footer
	\ifthenelse{\equal{\footerHeight}{0cm}}{
		%do nothing if footer should be of height 0
	}{
		\node(footercolored) at (bottomClipping.north west) [rectangle, minimum height=\footerHeight, minimum width=\paperwidth, draw=\pageHeaderFooterColor, fill=\pageHeaderFooterColor, inner sep=0pt, outer sep=0pt, anchor=south west] {};
	}			

	\node (spine) at (headercolored.south) [anchor=east, rotate=90, minimum width=\paperheight-\tClipping-\bClipping-\headerHeight-\footerHeight, text width= \paperheight-\tClipping-\bClipping-\headerHeight-\footerHeight-1.2cm] {#1};

\end{tikzpicture}
}

% text block with title node
\newcommand\segment[2]{
\begin{tikzpicture}
\ifthenelse{\isempty{#1}}{
	\node (textpart) at (rightClipping.north east) [anchor=north east, text width=\widthTextPart, align=center, rectangle,minimum width=\widthTextPart,inner sep=0pt,minimum height=1cm] {\centering #2};
	\node (segtitle) at (textpart.north west) [anchor=north east, outer sep=0pt, inner sep=0, minimum height=0cm, minimum width=\widthSegmentTitle, text width = \widthSegmentTitle-1cm] {};
}{
	\node (textpart) at (rightClipping.north east) [text width=\widthTextPart, align=center, rectangle,minimum width=\widthTextPart,inner xsep=0pt, inner ysep=8pt, minimum height=1cm] {#2};
	\node (segtitle) at (textpart.north west) [anchor=north east, outer sep=0pt, inner ysep=8pt, inner xsep=8pt, color=white, fill=\pageHeaderFooterColor, minimum height=1cm,minimum width=\widthSegmentTitle, text width = \widthSegmentTitle-1cm] {\large #1};
}	
%\ifthenelse{\boolean{netseries@print}}{
%	\node at (segtitle.north west) [anchor=north east, outer sep=0pt, inner sep=0, minimum height=0cm, minimum width=21cm+\spineWidth/2] {};
%}{}
\end{tikzpicture}
}

\newcommand\headline[1]{
\segment{}{\Large \bfseries{#1}

}
}
