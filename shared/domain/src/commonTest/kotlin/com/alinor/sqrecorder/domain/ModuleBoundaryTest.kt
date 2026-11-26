package com.alinor.sqrecorder.domain

import kotlin.test.Test
import kotlin.test.assertNotNull

class ModuleBoundaryTest {
    @Test
    fun moduleMarkerIsAvailable() {
        assertNotNull(ModuleBoundary)
    }
}
