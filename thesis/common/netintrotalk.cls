%
% netintrotalk.cls
%
%

%----------------------------------------------------------------------
% Identify class
%
\NeedsTeXFormat{LaTeX2e}[1999/12/01]
\ProvidesClass{netintrotalk}%
    [2015/06/09 v0.01.0 %
    netintrotalk.cls NET introduction talk class]

%----------------------------------------------------------------------
% Class options
%
\RequirePackage{kvoptions}%
\SetupKeyvalOptions{family=netintrotalk,prefix=netintrotalk@}%
% netcommon.sty
\DeclareVoidOption{english}{\PassOptionsToPackage{netcommon}{english} \PassOptionsToPackage{translator}{english}}%
\DeclareVoidOption{ngerman}{\PassOptionsToPackage{netcommon}{ngerman} \PassOptionsToPackage{translator}{ngerman}}%
\DeclareVoidOption{german}{\PassOptionsToPackage{netcommon}{german} \PassOptionsToPackage{translator}{german}}%
% type of work
\DeclareBoolOption[false]{idp}
\DeclareBoolOption[false]{bachelor}
\DeclareBoolOption[false]{master}
\DeclareBoolOption[false]{gr}

% Process options
\ProcessKeyvalOptions*\relax

%----------------------------------------------------------------------
% Load base class and required packages
%
\LoadClassWithOptions{article}
\RequirePackage[a4paper]{geometry}
\RequirePackage{amsmath}
\RequirePackage{fancyhdr}
\RequirePackage{netcommon}
\RequirePackage{translator}
\RequirePackage{pgfgantt}
\RequirePackage{etoolbox}
\RequirePackage[utf8]{inputenc}

%----------------------------------------------------------------------
% Variables
%
\def\thesistitle#1{\def\@thesistitle{#1}}
\def\supervisor#1{\def\@supervisor{#1}}


%----------------------------------------------------------------------
% Counter and commands for multiple advisors
%
\newcounter{numadvisors}

\newcommand\addadvisor[1]{%
\stepcounter{numadvisors}%
\csdef{advisor\thenumadvisors}{#1}}

\newcommand\getadvisor[1]{%
\csuse{advisor#1}}


%----------------------------------------------------------------------
% Language specific names and terms
%
\newcommand\idpnameenglish{Interdisciplinary Project}
\newcommand\idpnamegerman{Interdisziplin\"ares Projekt}
\newcommand\idpname{\idpnameenglish}

% Bachelor's Thesis and Master's Thesis are also used in German
% see http://www.in.tum.de/fuer-studierende/pruefungen-und-formalitaeten/abschlussarbeit.html
\newcommand\bachelorname{Bachelor's Thesis}
\newcommand\mastername{Master's Thesis}

\newcommand\grnameenglish{Guided Research Project}
\newcommand\grnamegerman{Forschungsarbeit unter Anleitung}
\newcommand\grname{\grnameenglish}

\newcommand\introtalknameenglish{Introduction Talk}
\newcommand\introtalknamegerman{Einf\"uhrungsgespr\"ach}
\newcommand\introtalkname{\introtalknameenglish}

\newcommand\supervisornameenglish{Supervisor}
\newcommand\supervisornamegerman{Themensteller}
\newcommand\supervisorname{\supervisornameenglish}

\newcommand\advisornameenglish{Advisor}
\newcommand\advisornamepluralenglish{Advisors}
\newcommand\advisornamegerman{Betreuer}
\newcommand\advisornamepluralgerman{\advisornamegerman}
\newcommand\advisorname{\advisornameenglish}
\newcommand\advisornameplural{\advisornamepluralenglish}

\newcommand\typeofworknameenglish{Type of Work}
\newcommand\typeofworknamegerman{Art der Arbeit}
\newcommand\typeofworkname{\typeofworknameenglish}

\newcommand\intronameenglish{Introduction}
\newcommand\intronamegerman{Einf\"uhrung}
\newcommand\introname{\intronameenglish}

\newcommand\approachnameenglish{Approach}
\newcommand\approachnamegerman{Ansatz}
\newcommand\approachname{\approachnameenglish}

\newcommand\schedulenameenglish{Schedule}
\newcommand\schedulenamegerman{Zeitplan}
\newcommand\schedulename{\schedulenameenglish}

\ifnet@german
    \renewcommand\grname{\grnamegerman}
    \renewcommand\idpname{\idpnamegerman}
    \renewcommand\introtalkname{\introtalknamegerman}
    \renewcommand\supervisorname{\supervisornamegerman}
    \renewcommand\advisorname{\advisornamegerman}
    \renewcommand\advisornameplural{\advisornamepluralgerman}
    \renewcommand\typeofworkname{\typeofworknamegerman}
    \renewcommand\introname{\intronamegerman}
    \renewcommand\approachname{\approachnamegerman}
    \renewcommand\schedulename{\schedulenamegerman}
\fi


%----------------------------------------------------------------------
% Macro for type of work
%
\newcommand{\typeofwork}{
\ifnetintrotalk@idp
\idpname
\fi
\ifnetintrotalk@bachelor
\bachelorname
\fi
\ifnetintrotalk@master
\mastername
\fi
\ifnetintrotalk@gr
\grname
\fi
}


%----------------------------------------------------------------------
% Header options
%
\setlength{\headheight}{55pt}
\renewcommand{\headrulewidth}{0pt}
\fancyhead[L]{
\NETlogo{height=1.5cm}
}
\fancyhead[R]{
\TUMlogo{height=1.5cm}
}


%----------------------------------------------------------------------
% Make the introduction talk header
%
\newcommand{\makeintroheader}{
\title{\@thesistitle \\
\large \introtalkname
}

\maketitle
\thispagestyle{fancy}

% Basic thesis info
\begin{flushleft}
\supervisorname:
\@supervisor \\
\ifnum\value{numadvisors}>1
\advisornameplural:
\else
\advisorname:
\fi
% Every thesis has at least one advisor
\newcounter{tempcnt}
\getadvisor{1}%
\stepcounter{tempcnt}%
\whileboolexpr{%
    test{\ifnumcomp{\value{tempcnt}}{<}{\value{numadvisors}}}}%
    {\stepcounter{tempcnt}, \getadvisor{\thetempcnt}}
\\
\typeofworkname: \typeofwork
\end{flushleft}
}


%----------------------------------------------------------------------
% Environment definitions
%
\newenvironment{intro}
{\section*{\introname}}
{}

\newenvironment{approach}
{\section*{\approachname}}
{}

\newenvironment{schedule}
{\section*{\schedulename}}
{}
