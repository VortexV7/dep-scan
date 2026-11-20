package com.depscan.ci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class CiDetectorTest {

    @Test
    void detectsEachCiVariable() {
        assertTrue(CiDetector.isCi(Map.of("CI", "true")));
        assertTrue(CiDetector.isCi(Map.of("GITHUB_ACTIONS", "true")));
        assertTrue(CiDetector.isCi(Map.of("GITLAB_CI", "true")));
        assertTrue(CiDetector.isCi(Map.of("JENKINS_URL", "http://jenkins/")));
        assertFalse(CiDetector.isCi(Map.of("CI", "false")));
        assertFalse(CiDetector.isCi(Map.of()));
    }

    @Test
    void ciNamePicksTheRightProvider() {
        assertEquals("GitHub Actions", CiDetector.ciName(Map.of("GITHUB_ACTIONS", "true")));
        assertEquals("GitLab CI", CiDetector.ciName(Map.of("GITLAB_CI", "true")));
        assertEquals("Jenkins", CiDetector.ciName(Map.of("JENKINS_URL", "http://x/")));
        assertEquals("", CiDetector.ciName(Map.of()));
    }

    @Test
    void gitHubGitLabJenkinsHelpers() {
        assertTrue(CiDetector.isGitHubActions(Map.of("GITHUB_ACTIONS", "true")));
        assertFalse(CiDetector.isGitHubActions(Map.of("GITLAB_CI", "true")));
        assertTrue(CiDetector.isGitLabCi(Map.of("GITLAB_CI", "true")));
        assertTrue(CiDetector.isJenkins(Map.of("JENKINS_URL", "http://x/")));
    }

    @Test
    void noColorEnv() {
        assertTrue(CiDetector.noColorEnv(Map.of("NO_COLOR", "1")));
        assertTrue(CiDetector.noColorEnv(Map.of("NO_COLOR", "")) == false);
        assertFalse(CiDetector.noColorEnv(Map.of()));
    }
}
