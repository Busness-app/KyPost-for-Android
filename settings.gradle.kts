pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Infomaniak's android-rich-html-editor (the compose screen's rich text body) is only
        // published to JitPack, not Maven Central.
        //
        // Scoped to that one group. JitPack builds artifacts on demand from git tags, and an
        // unfiltered entry makes it a candidate for *every* coordinate in the graph that is ever
        // missing upstream — while this dependency in particular owns a JavaScript-enabled WebView
        // with a bound @JavascriptInterface whose exportHtml feeds draft save and send. Resolution
        // order already means google() and mavenCentral() win for everything they hold, so this is
        // narrowing the blast radius rather than changing what resolves today.
        maven {
            url = uri("https://jitpack.io")
            content { includeGroup("com.github.infomaniak") }
        }
    }
}

rootProject.name = "kypost for android"
include(":app")
