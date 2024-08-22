<h1 align="center">CodeQL tailoring</h1>
<h3 align="center">One size does not always fit all</h3>

<p align="center">
  <a href="#mega-prerequisites">Prerequisites</a> •
  <a href="#books-resources">Resources</a> •
  <a href="#learning-objectives">Learning Objectives</a>
</p>

- **Who is this for**: Security Engineers, Security Researchers, Developers.
- **What you'll learn**: Learn how to use CodeQL for code exploration and for finding security issues.
- **What you'll build**: Build a CodeQL query based on a security advisory to find a SQL injection.

## Learning Objectives

In this workshop will cover the following learning objectives:

- Understand how to use CodeQL in exploration and identification of security vulnerabilities.
- Be able to codify a security vulnerability as a CodeQL query.
- Be able to refine queries to find variants and increase precision.
- Understand how refined queries can be integrated into the developer workflow to prevent future vulnerabilities.

## :mega: Prerequisites

Before joining the workshop, there are a few items that you will need to install or bring with you.

- Install [Visual Studio Code](https://code.visualstudio.com/).
- Install the [CodeQL extension](https://marketplace.visualstudio.com/items?itemName=github.vscode-codeql).
  <details><summary>Walkthrough</summary>

  ![Screenrecording demonstrating how to install the CodeQL extension](./assets/images/install-codeql-extension.gif)

  </details>
- Install the required CodeQL pack dependencies by running the command `CodeQL: Install pack dependencies` to install the dependencies for the pack `grehackworkshop/sql-injection-queries`.
  <details><summary>Walkthrough</summary>

  ![Screenrecording demonstrating how to install CodeQL pack dependencies](./assets/images/install-codeql-pack-deps.gif)

  </details>
- Install [git LFS](https://docs.github.com/en/repositories/working-with-files/managing-large-files/installing-git-large-file-storage) to download the prepared databases or build the databases locally using the provide Make file. The Makefile requires the presence of [Docker](https://www.docker.com/).
- Test your setup perform the steps:

  1. Right-click on the file [xwiki-platform-ratings-api-12.8-db.zip](./xwiki-platform-ratings-api-12.8-db.zip) and run the command `CodeQL: Set Current Database`.
  2. Right-click on the file [SqlInjection.ql](./java/sql-injection/src/SqlInjection.ql) and run the command `CodeQL: Run Queries in Selected Files`.
  3. See the result `Hello GreHack!` in the *CodeQL Query Results* pane.

   If you run into issues with your setup feel free to ask for support at the start of the workshop.

   <details><summary>Walkthrough</summary>

   ![Screencast demonstrating how to test your setup](./assets/images/test-setup.gif)

   </details>

After finishing the technical prerequisites consider the following tutorials/guides for basic understanding of QL and Java query writing:

- [QL tutorials](https://codeql.github.com/docs/writing-codeql-queries/ql-tutorials/)
- [Basic query for Java code](https://codeql.github.com/docs/codeql-language-guides/basic-query-for-java-code/)
- [QL classes](https://codeql.github.com/docs/ql-language-reference/types/#classes)

## :books: Resources

- [QL tutorials](https://codeql.github.com/docs/writing-codeql-queries/ql-tutorials/)
- [CodeQL for Java language guide](https://codeql.github.com/docs/codeql-language-guides/codeql-for-java/)
- [CodeQL documentation](https://codeql.github.com/docs/)
- [SQL injection](https://portswigger.net/web-security/sql-injection)
- [QL language reference](https://codeql.github.com/docs/ql-language-reference/)
- [CodeQL library for Java](https://codeql.github.com/codeql-standard-libraries/java/)

## Workshop

Welcome to the workshop findiing vunlnerabilities with CodeQL!
This session will introduce fundamentals of security research and static analysis used when looking for vulnerabilities in software. We will use an example of a simple vulnerability, walk through how CodeQL could detect it, and provide examples on how the audience could use CodeQL to find vulnerabilities themselves.

Before we get started it is important that all of the prerequisites are met so you can participate in the workshop.

The workshop is divided into multiple sections and each section consists of exercises that build up to the final query.
For each section we provide *hints* that help you finish the exercise by providing you with references to QL classes and member predicates that you can use.

### Overview

In this workshop we will look for a known *Command injection vulnerabilities* in the [XWiki Platform](https://xwiki.org)'s ratings API component. Such vulnerabilities can occur in applications when information that is controlled by a user makes its way to application code that insecurely construct a SQL query and executes it. SQL queries insecurely constructed from user input can be rewritten to perform unintended actions such as the disclosure of sensitive information.

The SQL injection discussed in this workshop is reviewed in [GHSA-79rg-7mv3-jrr5](https://github.com/advisories/GHSA-79rg-7mv3-jrr5) in [GitHub Advisory Database](https://github.com/advisories).

To find the SQL injection we are going to:

- Identify the vulnerable method discussed in the advisory and determine how it is used.
- Model the vulnerable method as a SQL sink so the SQL injection query is aware of this method.
- Identify how the vulnerable method can be used by finding new XWiki specific entrypoints.
- Model the new entrypoints as a source of untrusted data that can be used by CodeQL queries.

Once we have completed the above steps, we can see whether the models, our codified security knowledge, can uncover variants or possible
other security issues.

Let's start with finding more about the SQL injection.

## Theory

### Sources and sinks

Think about one of the most well-known vulnerabilities—command injection. It allows an attacker to execute operating system (OS) commands on the server that is running an application, and typically fully compromise the application and its data.

The main cause of injection vulnerabilities is untrusted, user-controlled input being used in sensitive or dangerous functions of the program. To represent these in static analysis, we use terms such as data flow, sources, and sinks.

User input generally comes from entry points to an application—the origin of data. These include parameters in HTTP methods, such as GET and POST, or command line arguments to a program. These are called “sources.”

Continuing with our SQL injection, an example of a dangerous function that should not be called with unsanitized untrusted data could be MySQLCursor.execute() from the MySQLdb library in Python or Python’s eval() built-in function which evaluates arbitrary expressions. These dangerous functions are called “sinks.” Note that just because a function is potentially dangerous, it does not mean it is immediately an exploitable vulnerability and has to be removed. Many sinks have ways of using them safely.

For a vulnerability to be present, the unsafe, user-controlled input has to be used without proper sanitization or input validation in a dangerous function. In other words, there has to be a code path between the source and the sink, in which case we say that data flows from a source to a sink—there is a “data flow” from the source to the sink.

### Basic CodeQL query

## Workshop part I - test database

In the security advisory [GHSA-79rg-7mv3-jrr5](https://github.com/advisories/GHSA-79rg-7mv3-jrr5) in [GitHub Advisory Database](https://github.com/advisories) we learn of a [Jira issue](https://jira.xwiki.org/browse/XWIKI-17662) that discusses SQL injection in more detail.

From the Jira issue we learn that:

1. There exists a method `getAverageRating` in the `Rating Script Service`.
2. The two parameters of `getAverageRating` are used in the class `AbstractRatingManager` to insecurely construct a SQL statement.

We will use CodeQL to find the method and use the results to better understand how the SQL injection can manifest.

Select the database [xwiki-platform-ratings-api-12.8-db.zip] as the current database by right-clicking on it in the *Explorer* and executing the command *CodeQL: Set current database*.

The following steps can be implemented in the exercise file [SqlInjection.ql](./java/sql-injection/src/SqlInjection.ql)

### 1. Find all calls to functions from external libraries

<details>
<summary>Hints</summary>

```codeql
dssdf
```

</details>
<details>
<summary>Solution</summary>

```codeql
import python
import semmle.python.ApiGraphs

from API::CallNode call
where call.getLocation().getFile().getRelativePath().regexpMatch("test-app/.*")
select call
```

</details>
