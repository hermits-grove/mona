//
//  AuthViewController.swift
//  mona
//
//  Created by David Rusu on 2018-05-15.
//  Copyright © 2018 David Rusu. All rights reserved.
//

import Cocoa

class AuthViewController: NSViewController, NSWindowDelegate {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        view.wantsLayer = true
        view.layer?.contents = #imageLiteral(resourceName: "castle-castle-fairy-tale-1909")
    }
}
