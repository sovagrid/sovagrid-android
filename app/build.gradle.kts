/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val previewStorePath = providers.environmentVariable("SOVAGRID_ANDROID_SIGNING_STORE_FILE").orNull
val previewStorePassword = providers.environmentVariable("SOVAGRID_ANDROID_SIGNING_PASSWORD").orNull
check((previewStorePath == null) == (previewStorePassword == null)) {
    "Preview signing requires both store file and password environment variables"
}

android {
    namespace = "org.sovagrid.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.sovagrid.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 16
        versionName = "0.8.0"
        testInstrumentationRunner = "org.sovagrid.android.SshKeyVaultInstrumentation"
    }

    signingConfigs {
        if (previewStorePath != null && previewStorePassword != null) {
            create("preview") {
                storeFile = file(previewStorePath)
                storePassword = previewStorePassword
                keyAlias = "sovagrid-preview"
                keyPassword = previewStorePassword
                storeType = "PKCS12"
            }
        }
    }

    buildTypes {
        getByName("debug") {
            if (previewStorePath != null) signingConfig = signingConfigs.getByName("preview")
        }
        release {
            isMinifyEnabled = false
            if (previewStorePath != null) signingConfig = signingConfigs.getByName("preview")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets.getByName("main").assets.srcDir(layout.buildDirectory.dir("generated/legal-assets"))

}

val packageLegalNotices by tasks.registering(Copy::class) {
    val notices = listOf("LICENSE", "ATTRIBUTION.md", "NOTICE", "THIRD_PARTY_NOTICES.txt")
    from(notices.map { rootProject.layout.projectDirectory.file(it) })
    into(layout.buildDirectory.dir("generated/legal-assets/legal"))
    doFirst {
        notices.forEach { name ->
            check(rootProject.file(name).isFile) { "Missing required legal notice: $name" }
        }
    }
}

tasks.matching { task ->
    (task.name.startsWith("merge") && task.name.endsWith("Assets")) ||
        task.name.contains("lint", ignoreCase = true)
}.configureEach { dependsOn(packageLegalNotices) }

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":ssh-core"))
    implementation("androidx.webkit:webkit:1.18.0")
    runtimeOnly("org.slf4j:slf4j-nop:2.0.17")
    testImplementation("junit:junit:4.13.2")
}
