//
//  MainWindowController.swift
//  mona
//
//  Created by David Rusu on 2018-05-15.
//  Copyright © 2018 David Rusu. All rights reserved.
//

import Cocoa

class MainWindowController: NSWindowController {

    convenience init() {
        self.init(windowNibName: NSNib.Name(rawValue: "MainWindowController"))
    }
    
    override func windowDidLoad() {
        super.windowDidLoad()

        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
        window?.contentViewController = AuthViewController()
    }
}
