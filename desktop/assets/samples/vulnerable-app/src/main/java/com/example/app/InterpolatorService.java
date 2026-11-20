package com.example.app;

import org.apache.commons.text.StringSubstitutor;

/** Multi-hop step between main and the vulnerable library call. */
public class InterpolatorService {
    public String interpolate(String input) {
        // CVE-2022-42889: StringSubstitutor.createInterpolator() enables
        // script / DNS / URL lookups from untrusted input.
        return StringSubstitutor.createInterpolator().replace(input);
    }
}
